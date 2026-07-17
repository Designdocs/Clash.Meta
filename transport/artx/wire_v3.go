package artx

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

const (
	wireV3Version            = byte(0x03)
	wireV3Flags              = byte(0x00)
	wireV3SaltLength         = 16
	wireV3ExporterLength     = sha256.Size
	wireV3TagLength          = sha256.Size
	wireV3MaxDestinationSize = 259
	wireV3ExporterLabel      = "EXPORTER-artx-auth-v3"
	wireV3ClientLabel        = "artx-wire-v3-client\x00"
	wireV3ServerLabel        = "artx-wire-v3-server\x00"
	wireV3Path               = "/"
)

const wireV3ClientInitPrefixSize = 1 + 1 + 1 + 2 + wireV3SaltLength + 8 + 4

type wireV3ClientInit struct {
	Salt            [wireV3SaltLength]byte
	UserLocator     [8]byte
	TimestampBucket uint32
	Destination     []byte
	ClientTag       [wireV3TagLength]byte
}

func newWireV3ClientInit(psk, salt, exporter []byte, authority, path string, destination []byte, timestampBucket uint32) (wireV3ClientInit, error) {
	if len(psk) == 0 {
		return wireV3ClientInit{}, errors.New("artx wire-v3 PSK is empty")
	}
	if len(salt) != wireV3SaltLength {
		return wireV3ClientInit{}, fmt.Errorf("artx wire-v3 salt length is %d, want %d", len(salt), wireV3SaltLength)
	}
	if len(exporter) != wireV3ExporterLength {
		return wireV3ClientInit{}, fmt.Errorf("artx wire-v3 exporter length is %d, want %d", len(exporter), wireV3ExporterLength)
	}
	if err := validateWireV3Context(authority, path, destination); err != nil {
		return wireV3ClientInit{}, err
	}
	init := wireV3ClientInit{UserLocator: calculateUserLocator(psk), TimestampBucket: timestampBucket, Destination: append([]byte(nil), destination...)}
	copy(init.Salt[:], salt)
	prefix, _ := init.marshalPrefix()
	init.ClientTag = calculateWireV3ClientTag(psk, exporter, authority, path, prefix)
	return init, nil
}

func (init wireV3ClientInit) MarshalBinary() ([]byte, error) {
	prefix, err := init.marshalPrefix()
	if err != nil {
		return nil, err
	}
	return append(prefix, init.ClientTag[:]...), nil
}

func (init wireV3ClientInit) marshalPrefix() ([]byte, error) {
	if len(init.Destination) == 0 || len(init.Destination) > wireV3MaxDestinationSize {
		return nil, fmt.Errorf("artx wire-v3 destination length is %d", len(init.Destination))
	}
	prefix := make([]byte, wireV3ClientInitPrefixSize+len(init.Destination))
	prefix[0], prefix[1], prefix[2] = wireV3Version, wireV3Flags, wireV3SaltLength
	binary.BigEndian.PutUint16(prefix[3:5], uint16(len(init.Destination)))
	offset := 5
	copy(prefix[offset:], init.Salt[:])
	offset += wireV3SaltLength
	copy(prefix[offset:], init.UserLocator[:])
	offset += len(init.UserLocator)
	binary.BigEndian.PutUint32(prefix[offset:], init.TimestampBucket)
	offset += 4
	copy(prefix[offset:], init.Destination)
	return prefix, nil
}

func parseWireV3ClientInit(envelope []byte) (wireV3ClientInit, error) {
	if len(envelope) < wireV3ClientInitPrefixSize+1+wireV3TagLength {
		return wireV3ClientInit{}, errors.New("artx wire-v3 ClientInit is truncated")
	}
	if envelope[0] != wireV3Version || envelope[1] != wireV3Flags || envelope[2] != wireV3SaltLength {
		return wireV3ClientInit{}, errors.New("invalid artx wire-v3 ClientInit header")
	}
	destinationLength := int(binary.BigEndian.Uint16(envelope[3:5]))
	if destinationLength == 0 || destinationLength > wireV3MaxDestinationSize {
		return wireV3ClientInit{}, errors.New("invalid artx wire-v3 destination length")
	}
	if len(envelope) != wireV3ClientInitPrefixSize+destinationLength+wireV3TagLength {
		return wireV3ClientInit{}, errors.New("invalid artx wire-v3 ClientInit length")
	}
	init := wireV3ClientInit{Destination: make([]byte, destinationLength)}
	offset := 5
	copy(init.Salt[:], envelope[offset:])
	offset += wireV3SaltLength
	copy(init.UserLocator[:], envelope[offset:])
	offset += len(init.UserLocator)
	init.TimestampBucket = binary.BigEndian.Uint32(envelope[offset:])
	offset += 4
	copy(init.Destination, envelope[offset:offset+destinationLength])
	offset += destinationLength
	copy(init.ClientTag[:], envelope[offset:])
	return init, nil
}

func (init wireV3ClientInit) Verify(psk, exporter []byte, authority, path string) bool {
	if len(psk) == 0 || len(exporter) != wireV3ExporterLength || validateWireV3Context(authority, path, init.Destination) != nil {
		return false
	}
	prefix, err := init.marshalPrefix()
	if err != nil {
		return false
	}
	want := calculateWireV3ClientTag(psk, exporter, authority, path, prefix)
	return hmac.Equal(init.ClientTag[:], want[:])
}

func calculateWireV3ClientTag(psk, exporter []byte, authority, path string, prefix []byte) [wireV3TagLength]byte {
	mac := hmac.New(sha256.New, psk)
	_, _ = mac.Write([]byte(wireV3ClientLabel))
	_, _ = mac.Write(exporter)
	writeWireV3LengthPrefixed(mac, authority)
	writeWireV3LengthPrefixed(mac, path)
	_, _ = mac.Write(prefix)
	var tag [wireV3TagLength]byte
	copy(tag[:], mac.Sum(nil))
	return tag
}

func calculateWireV3ServerProof(psk, exporter []byte, clientTag [wireV3TagLength]byte, status int) [wireV3TagLength]byte {
	mac := hmac.New(sha256.New, psk)
	_, _ = mac.Write([]byte(wireV3ServerLabel))
	_, _ = mac.Write(exporter)
	_, _ = mac.Write(clientTag[:])
	var encodedStatus [2]byte
	binary.BigEndian.PutUint16(encodedStatus[:], uint16(status))
	_, _ = mac.Write(encodedStatus[:])
	var proof [wireV3TagLength]byte
	copy(proof[:], mac.Sum(nil))
	return proof
}

func formatWireV3Authorization(init wireV3ClientInit) string {
	envelope, err := init.MarshalBinary()
	if err != nil {
		return ""
	}
	return "Bearer " + base64.RawURLEncoding.EncodeToString(envelope)
}

func parseWireV3Authorization(header string) (wireV3ClientInit, bool, error) {
	if !strings.HasPrefix(header, "Bearer ") {
		return wireV3ClientInit{}, false, nil
	}
	maxEnvelopeLength := wireV3ClientInitPrefixSize + wireV3MaxDestinationSize + wireV3TagLength
	if len(header) > len("Bearer ")+base64.RawURLEncoding.EncodedLen(maxEnvelopeLength) {
		return wireV3ClientInit{}, true, errors.New("oversized artx wire-v3 Authorization")
	}
	encoded := strings.TrimPrefix(header, "Bearer ")
	if encoded == "" || strings.TrimSpace(encoded) != encoded {
		return wireV3ClientInit{}, true, errors.New("malformed artx wire-v3 Authorization")
	}
	envelope, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return wireV3ClientInit{}, true, errors.New("malformed artx wire-v3 Authorization")
	}
	init, err := parseWireV3ClientInit(envelope)
	return init, true, err
}

func formatWireV3AuthenticationInfo(proof [wireV3TagLength]byte) string {
	return `rspauth="` + base64.RawURLEncoding.EncodeToString(proof[:]) + `"`
}

func verifyWireV3AuthenticationInfo(header string, psk, exporter []byte, clientTag [wireV3TagLength]byte, status int) bool {
	prefix := `rspauth="`
	if !strings.HasPrefix(header, prefix) || !strings.HasSuffix(header, `"`) || len(header) <= len(prefix)+1 {
		return false
	}
	encoded := header[len(prefix) : len(header)-1]
	proof, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(proof) != wireV3TagLength {
		return false
	}
	want := calculateWireV3ServerProof(psk, exporter, clientTag, status)
	return hmac.Equal(proof, want[:])
}

func validateWireV3Context(authority, path string, destination []byte) error {
	if authority == "" || len(authority) > int(^uint16(0)) {
		return errors.New("invalid artx wire-v3 authority")
	}
	if path == "" || len(path) > int(^uint16(0)) {
		return errors.New("invalid artx wire-v3 path")
	}
	if len(destination) == 0 || len(destination) > wireV3MaxDestinationSize {
		return errors.New("invalid artx wire-v3 destination")
	}
	return nil
}

func writeWireV3LengthPrefixed(mac interface{ Write([]byte) (int, error) }, value string) {
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(value)))
	_, _ = mac.Write(length[:])
	_, _ = mac.Write([]byte(value))
}

func dialWireV3Context(ctx context.Context, raw net.Conn, config ClientConfig, destination Destination) (_ net.Conn, err error) {
	if err := destination.Validate(); err != nil {
		return nil, err
	}
	if err := validateClientConfig(raw, config, 3); err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = raw.Close()
		}
	}()
	stopContextClose := context.AfterFunc(ctx, func() { _ = raw.Close() })
	defer stopContextClose()

	tlsConnection, state, err := dialArtXTLS(ctx, raw, config, []string{http2.NextProtoTLS})
	if err != nil {
		return nil, err
	}
	if state.NegotiatedProtocol != http2.NextProtoTLS || state.DidResume {
		_ = tlsConnection.Close()
		return nil, errors.New("artx wire-v3 requires fresh TLS with h2 ALPN")
	}
	exporter, err := state.ExportKeyingMaterial(wireV3ExporterLabel, nil, wireV3ExporterLength)
	if err != nil {
		_ = tlsConnection.Close()
		return nil, fmt.Errorf("artx wire-v3 TLS exporter: %w", err)
	}
	salt := make([]byte, wireV3SaltLength)
	if _, err := rand.Read(salt); err != nil {
		_ = tlsConnection.Close()
		return nil, err
	}
	init, err := newWireV3ClientInit([]byte(config.Password), salt, exporter, config.Authority, wireV3Path, destination.MarshalBinary(), uint32(time.Now().Unix()/bucketSeconds))
	if err != nil {
		_ = tlsConnection.Close()
		return nil, err
	}

	connectionContext, cancel := context.WithCancel(context.Background())
	requestReader, requestWriter := io.Pipe()
	request, err := http.NewRequestWithContext(connectionContext, http.MethodPost, "https://"+config.Authority+wireV3Path, requestReader)
	if err != nil {
		cancel()
		_ = requestReader.Close()
		_ = requestWriter.Close()
		_ = tlsConnection.Close()
		return nil, err
	}
	request.Host = config.Authority
	request.Header.Set("Authorization", formatWireV3Authorization(init))
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("User-Agent", "")
	clientConnection, err := new(http2.Transport).NewClientConn(tlsConnection)
	if err != nil {
		cancel()
		_ = requestReader.Close()
		_ = requestWriter.Close()
		_ = tlsConnection.Close()
		return nil, err
	}
	response, err := clientConnection.RoundTrip(request)
	if err != nil {
		cancel()
		_ = requestWriter.CloseWithError(err)
		_ = clientConnection.Close()
		return nil, err
	}
	proofValid := verifyWireV3AuthenticationInfo(response.Header.Get("Authentication-Info"), []byte(config.Password), exporter, init.ClientTag, response.StatusCode)
	if response.StatusCode != http.StatusOK || !proofValid || response.Header.Get("Content-Type") != "application/octet-stream" || response.Header.Get("Cache-Control") != "no-store" {
		cancel()
		_ = response.Body.Close()
		_ = requestWriter.CloseWithError(errors.New("artx wire-v3 response rejected"))
		_ = clientConnection.Close()
		return nil, errors.New("artx wire-v3 authentication response rejected")
	}
	if !stopContextClose() {
		cancel()
		_ = response.Body.Close()
		_ = requestWriter.CloseWithError(ctx.Err())
		_ = clientConnection.Close()
		return nil, ctx.Err()
	}
	return &wireV3Conn{
		Conn:     tlsConnection,
		upload:   requestWriter,
		download: response.Body,
		client:   clientConnection,
		cancel:   cancel,
	}, nil
}

type wireV3Conn struct {
	net.Conn
	upload   *io.PipeWriter
	download io.ReadCloser
	client   *http2.ClientConn
	cancel   context.CancelFunc
	closeMu  sync.Mutex
	closed   bool
}

func (connection *wireV3Conn) Read(payload []byte) (int, error) {
	read, err := connection.download.Read(payload)
	if err != nil {
		_ = connection.closeOuter(err)
	}
	return read, err
}

func (connection *wireV3Conn) Write(payload []byte) (int, error) {
	written, err := connection.upload.Write(payload)
	if err != nil {
		_ = connection.closeOuter(err)
	}
	return written, err
}

func (connection *wireV3Conn) CloseWrite() error {
	err := connection.upload.Close()
	if err != nil {
		_ = connection.closeOuter(err)
	}
	return err
}

func (connection *wireV3Conn) Close() error {
	return connection.closeOuter(net.ErrClosed)
}

func (connection *wireV3Conn) closeOuter(closeErr error) error {
	connection.closeMu.Lock()
	defer connection.closeMu.Unlock()
	if connection.closed {
		return nil
	}
	connection.closed = true
	connection.cancel()
	if closeErr == nil {
		_ = connection.upload.Close()
	} else {
		_ = connection.upload.CloseWithError(closeErr)
	}
	_ = connection.download.Close()
	_ = connection.client.Close()
	return connection.Conn.Close()
}
