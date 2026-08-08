package artx

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	N "github.com/metacubex/mihomo/common/net"
)

const wireV4MaxHeaderSize = 16 << 10

const (
	wireV4Version        = byte(0x04)
	wireV4Flags          = byte(0x00)
	wireV4SaltLength     = 16
	wireV4ExporterLength = sha256.Size
	wireV4TagLength      = sha256.Size
	wireV4ExporterLabel  = "EXPORTER-artx-auth-v4"
	wireV4ClientLabel    = "artx-wire-v4-client\x00"
	wireV4ServerLabel    = "artx-wire-v4-server\x00"
	wireV4Method         = "CONNECT"
)

const (
	wireV4ClientInitPrefixSize = 1 + 1 + wireV4SaltLength + 8 + 4
	wireV4ClientInitSize       = wireV4ClientInitPrefixSize + wireV4TagLength
)

type wireV4ClientInit struct {
	Salt            [wireV4SaltLength]byte
	UserLocator     [8]byte
	TimestampBucket uint32
	ClientTag       [wireV4TagLength]byte
}

func newWireV4ClientInit(psk, salt, exporter []byte, serverName, targetAuthority string, timestampBucket uint32) (wireV4ClientInit, error) {
	if len(psk) == 0 {
		return wireV4ClientInit{}, errors.New("artx wire-v4 PSK is empty")
	}
	if len(salt) != wireV4SaltLength {
		return wireV4ClientInit{}, fmt.Errorf("artx wire-v4 salt length is %d, want %d", len(salt), wireV4SaltLength)
	}
	if len(exporter) != wireV4ExporterLength {
		return wireV4ClientInit{}, fmt.Errorf("artx wire-v4 exporter length is %d, want %d", len(exporter), wireV4ExporterLength)
	}
	if err := validateWireV4Context(serverName, targetAuthority); err != nil {
		return wireV4ClientInit{}, err
	}
	init := wireV4ClientInit{
		UserLocator:     calculateUserLocator(psk),
		TimestampBucket: timestampBucket,
	}
	copy(init.Salt[:], salt)
	init.ClientTag = calculateWireV4ClientTag(psk, exporter, serverName, targetAuthority, init.marshalPrefix())
	return init, nil
}

func (init wireV4ClientInit) MarshalBinary() ([]byte, error) {
	prefix := init.marshalPrefix()
	return append(prefix, init.ClientTag[:]...), nil
}

func (init wireV4ClientInit) marshalPrefix() []byte {
	prefix := make([]byte, wireV4ClientInitPrefixSize)
	prefix[0], prefix[1] = wireV4Version, wireV4Flags
	offset := 2
	copy(prefix[offset:], init.Salt[:])
	offset += wireV4SaltLength
	copy(prefix[offset:], init.UserLocator[:])
	offset += len(init.UserLocator)
	binary.BigEndian.PutUint32(prefix[offset:], init.TimestampBucket)
	return prefix
}

func parseWireV4ClientInit(envelope []byte) (wireV4ClientInit, error) {
	if len(envelope) != wireV4ClientInitSize {
		return wireV4ClientInit{}, errors.New("invalid artx wire-v4 ClientInit length")
	}
	if envelope[0] != wireV4Version || envelope[1] != wireV4Flags {
		return wireV4ClientInit{}, errors.New("invalid artx wire-v4 ClientInit header")
	}
	var init wireV4ClientInit
	offset := 2
	copy(init.Salt[:], envelope[offset:])
	offset += wireV4SaltLength
	copy(init.UserLocator[:], envelope[offset:])
	offset += len(init.UserLocator)
	init.TimestampBucket = binary.BigEndian.Uint32(envelope[offset:])
	offset += 4
	copy(init.ClientTag[:], envelope[offset:])
	return init, nil
}

func (init wireV4ClientInit) Verify(psk, exporter []byte, serverName, targetAuthority string) bool {
	if len(psk) == 0 || len(exporter) != wireV4ExporterLength || validateWireV4Context(serverName, targetAuthority) != nil {
		return false
	}
	want := calculateWireV4ClientTag(psk, exporter, serverName, targetAuthority, init.marshalPrefix())
	return hmac.Equal(init.ClientTag[:], want[:])
}

func calculateWireV4ClientTag(psk, exporter []byte, serverName, targetAuthority string, prefix []byte) [wireV4TagLength]byte {
	mac := hmac.New(sha256.New, psk)
	_, _ = mac.Write([]byte(wireV4ClientLabel))
	_, _ = mac.Write(exporter)
	writeWireV4LengthPrefixed(mac, serverName)
	writeWireV4LengthPrefixed(mac, wireV4Method)
	writeWireV4LengthPrefixed(mac, targetAuthority)
	_, _ = mac.Write(prefix)
	var tag [wireV4TagLength]byte
	copy(tag[:], mac.Sum(nil))
	return tag
}

func calculateWireV4ServerProof(psk, exporter []byte, clientTag [wireV4TagLength]byte, status int) [wireV4TagLength]byte {
	mac := hmac.New(sha256.New, psk)
	_, _ = mac.Write([]byte(wireV4ServerLabel))
	_, _ = mac.Write(exporter)
	_, _ = mac.Write(clientTag[:])
	var encodedStatus [2]byte
	binary.BigEndian.PutUint16(encodedStatus[:], uint16(status))
	_, _ = mac.Write(encodedStatus[:])
	var proof [wireV4TagLength]byte
	copy(proof[:], mac.Sum(nil))
	return proof
}

func formatWireV4ProxyAuthorization(init wireV4ClientInit) string {
	envelope, _ := init.MarshalBinary()
	return "Bearer " + base64.RawURLEncoding.EncodeToString(envelope)
}

func parseWireV4ProxyAuthorization(header string) (wireV4ClientInit, bool, error) {
	if !strings.HasPrefix(header, "Bearer ") {
		return wireV4ClientInit{}, false, nil
	}
	encoded := strings.TrimPrefix(header, "Bearer ")
	if len(encoded) != base64.RawURLEncoding.EncodedLen(wireV4ClientInitSize) || strings.TrimSpace(encoded) != encoded {
		return wireV4ClientInit{}, true, errors.New("malformed artx wire-v4 Proxy-Authorization")
	}
	envelope, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(envelope) != encoded {
		return wireV4ClientInit{}, true, errors.New("malformed artx wire-v4 Proxy-Authorization")
	}
	init, err := parseWireV4ClientInit(envelope)
	return init, true, err
}

func formatWireV4ProxyAuthenticationInfo(proof [wireV4TagLength]byte) string {
	return `rspauth="` + base64.RawURLEncoding.EncodeToString(proof[:]) + `"`
}

func verifyWireV4ProxyAuthenticationInfo(header string, psk, exporter []byte, clientTag [wireV4TagLength]byte, status int) bool {
	prefix := `rspauth="`
	encodedLength := base64.RawURLEncoding.EncodedLen(wireV4TagLength)
	if len(header) != len(prefix)+encodedLength+1 || !strings.HasPrefix(header, prefix) || !strings.HasSuffix(header, `"`) {
		return false
	}
	encoded := header[len(prefix) : len(header)-1]
	proof, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(proof) != wireV4TagLength || base64.RawURLEncoding.EncodeToString(proof) != encoded {
		return false
	}
	want := calculateWireV4ServerProof(psk, exporter, clientTag, status)
	return hmac.Equal(proof, want[:])
}

func validateWireV4Context(serverName, targetAuthority string) error {
	if net.ParseIP(serverName) != nil {
		return errors.New("invalid artx wire-v4 server name")
	}
	canonicalServerName, err := canonicalWireV4Domain(serverName)
	if err != nil || canonicalServerName != serverName {
		return errors.New("invalid artx wire-v4 server name")
	}
	_, err = parseWireV4Authority(targetAuthority)
	return err
}

func formatWireV4Authority(destination Destination) (string, error) {
	if err := destination.Validate(); err != nil {
		return "", err
	}
	var host string
	if destination.Host != "" {
		var err error
		host, err = canonicalWireV4Domain(destination.Host)
		if err != nil {
			return "", err
		}
	} else {
		if destination.IP.Zone() != "" {
			return "", errors.New("invalid artx wire-v4 zoned IP destination")
		}
		host = destination.IP.Unmap().String()
		if host == "" {
			return "", errors.New("invalid artx wire-v4 IP destination")
		}
	}
	return net.JoinHostPort(host, strconv.Itoa(int(destination.Port))), nil
}

func parseWireV4Authority(authority string) (Destination, error) {
	host, portText, err := net.SplitHostPort(authority)
	if err != nil || host == "" || portText == "" {
		return Destination{}, errors.New("invalid artx wire-v4 authority")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 || strconv.Itoa(port) != portText {
		return Destination{}, errors.New("invalid artx wire-v4 authority port")
	}
	var destination Destination
	if ip, ipErr := netip.ParseAddr(host); ipErr == nil {
		if ip.Zone() != "" {
			return Destination{}, errors.New("invalid artx wire-v4 zoned authority")
		}
		destination = Destination{IP: ip.Unmap(), Port: uint16(port)}
	} else {
		canonicalHost, hostErr := canonicalWireV4Domain(host)
		if hostErr != nil || canonicalHost != host {
			return Destination{}, errors.New("non-canonical artx wire-v4 authority host")
		}
		destination = Destination{Host: host, Port: uint16(port)}
	}
	canonical, err := formatWireV4Authority(destination)
	if err != nil || canonical != authority {
		return Destination{}, errors.New("non-canonical artx wire-v4 authority")
	}
	return destination, nil
}

func canonicalWireV4Domain(value string) (string, error) {
	value = strings.TrimSuffix(strings.ToLower(value), ".")
	if value == "" || len(value) > 253 {
		return "", errors.New("invalid artx wire-v4 domain")
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || !wireV4DomainEdge(label[0]) || !wireV4DomainEdge(label[len(label)-1]) {
			return "", errors.New("invalid artx wire-v4 domain label")
		}
		for index := 1; index < len(label)-1; index++ {
			if !wireV4DomainEdge(label[index]) && label[index] != '-' {
				return "", errors.New("invalid artx wire-v4 domain label")
			}
		}
	}
	return value, nil
}

func wireV4DomainEdge(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}

func writeWireV4LengthPrefixed(writer interface{ Write([]byte) (int, error) }, value string) {
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(value)))
	_, _ = writer.Write(length[:])
	_, _ = writer.Write([]byte(value))
}

func dialWireV4Context(ctx context.Context, raw net.Conn, config ClientConfig, destination Destination, r0 r0Hook) (_ net.Conn, err error) {
	if err := destination.Validate(); err != nil {
		return nil, err
	}
	if err := validateClientConfig(raw, config, 4); err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = raw.Close()
		}
	}()
	stopContextClose := context.AfterFunc(ctx, func() { _ = raw.Close() })
	defer stopContextClose()

	tlsConnection, state, err := dialArtXTLS(ctx, raw, config, []string{"http/1.1"})
	if err != nil {
		return nil, err
	}
	emitR0Event(r0, r0PhaseSetup, r0EventTLSReady, 1)
	if state.NegotiatedProtocol != "http/1.1" || state.DidResume {
		return nil, errors.New("artx wire-v4 requires fresh TLS with HTTP/1.1 ALPN")
	}
	targetAuthority, err := formatWireV4Authority(destination)
	if err != nil {
		return nil, err
	}
	exporter, err := state.ExportKeyingMaterial(wireV4ExporterLabel, nil, wireV4ExporterLength)
	if err != nil {
		return nil, fmt.Errorf("artx wire-v4 TLS exporter: %w", err)
	}
	salt := make([]byte, wireV4SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	init, err := newWireV4ClientInit([]byte(config.Password), salt, exporter, config.Authority, targetAuthority, uint32(time.Now().Unix()/bucketSeconds))
	if err != nil {
		return nil, err
	}
	request := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: targetAuthority},
		Host:   targetAuthority,
		Header: make(http.Header),
	}
	request.Header.Set("Proxy-Authorization", formatWireV4ProxyAuthorization(init))
	request.Header.Set("User-Agent", "")
	requestWriter := observeR0Writer(r0, r0PhaseSetup, r0EventClientOpenWrite, tlsConnection)
	if err := request.Write(requestWriter); err != nil {
		return nil, err
	}
	emitR0Event(r0, r0PhaseSetup, r0EventProofWait, 1)

	response, reader, responseHeader, err := readWireV4Response(tlsConnection, request)
	if err != nil {
		return nil, err
	}
	proofValid := len(response.Header.Values("Proxy-Authentication-Info")) == 1 && verifyWireV4ProxyAuthenticationInfo(
		response.Header.Get("Proxy-Authentication-Info"), []byte(config.Password), exporter, init.ClientTag, response.StatusCode,
	)
	proofResult := uint8(2)
	if proofValid {
		proofResult = 1
	}
	emitR0Event(r0, r0PhaseSetup, r0EventProofChecked, proofResult)
	validResponse := response.ProtoMajor == 1 && response.ProtoMinor == 1 &&
		response.StatusCode == http.StatusOK && proofValid &&
		len(response.Header.Values("Cache-Control")) == 1 && response.Header.Get("Cache-Control") == "no-store" &&
		!wireV4ResponseHasForbiddenHeader(responseHeader)
	if !validResponse {
		return nil, errors.New("artx wire-v4 authentication response rejected")
	}
	emitR0Event(r0, r0PhaseSetup, r0EventProofVerified, 1)
	if err := finishWireV4HandshakeContext(ctx, stopContextClose); err != nil {
		return nil, err
	}
	emitR0Event(r0, r0PhaseSetup, r0EventInnerExposed, 1)
	return N.WarpConnWithBioReader(tlsConnection, reader), nil
}

func finishWireV4HandshakeContext(ctx context.Context, stop func() bool) error {
	stopped := stop()
	if err := ctx.Err(); err != nil {
		return err
	}
	if !stopped {
		return errors.New("artx wire-v4 handshake context ended")
	}
	return nil
}

func readWireV4Response(connection net.Conn, request *http.Request) (*http.Response, *bufio.Reader, []byte, error) {
	reader := bufio.NewReader(connection)
	header := make([]byte, 0, 512)
	for !bytes.HasSuffix(header, []byte("\r\n\r\n")) {
		fragment, err := reader.ReadSlice('\n')
		if len(header)+len(fragment) > wireV4MaxHeaderSize {
			return nil, nil, nil, errors.New("artx wire-v4 response header is too large")
		}
		header = append(header, fragment...)
		if err != nil && !errors.Is(err, bufio.ErrBufferFull) {
			return nil, nil, nil, err
		}
	}
	response, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(header)), request)
	if err != nil {
		return nil, nil, nil, err
	}
	return response, reader, header, nil
}

func wireV4ResponseHasForbiddenHeader(header []byte) bool {
	lines := bytes.Split(header, []byte("\r\n"))
	for _, line := range lines[1:] {
		if len(line) == 0 {
			break
		}
		if line[0] == ' ' || line[0] == '\t' {
			return true
		}
		name, _, found := bytes.Cut(line, []byte{':'})
		if !found {
			return true
		}
		for _, forbidden := range []string{"Content-Length", "Transfer-Encoding", "Connection", "Upgrade", "Proxy-Authenticate", "WWW-Authenticate"} {
			if strings.EqualFold(string(name), forbidden) {
				return true
			}
		}
	}
	return false
}
