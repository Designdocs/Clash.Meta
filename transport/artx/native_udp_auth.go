package artx

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"strings"
)

const (
	nativeUDPExporterLabel  = "EXPORTER-artx-native-udp-v0"
	nativeUDPExporterLength = sha256.Size
	nativeUDPAuthHeader     = "Proxy-Authorization"
	nativeUDPProofHeader    = "Proxy-Authentication-Info"

	nativeUDPAuthVersion = byte(1)
	nativeUDPAuthFlags   = byte(0)
	nativeUDPSaltLength  = 16
	nativeUDPTagLength   = sha256.Size
	nativeUDPClientLabel = "artx-native-udp-client-v0\x00"
	nativeUDPServerLabel = "artx-native-udp-server-v0\x00"
)

const (
	nativeUDPAuthPrefixSize = 2 + nativeUDPSaltLength + 8 + 4
	nativeUDPAuthSize       = nativeUDPAuthPrefixSize + nativeUDPTagLength
)

type nativeUDPRequest struct {
	method          string
	protocol        string
	scheme          string
	authority       string
	path            string
	capsuleProtocol string
}

type nativeUDPAuthorization struct {
	salt      [nativeUDPSaltLength]byte
	locator   [8]byte
	bucket    uint32
	clientTag [nativeUDPTagLength]byte
}

func newNativeUDPAuthorization(psk, salt, exporter []byte, request nativeUDPRequest, bucket uint32) (nativeUDPAuthorization, error) {
	if len(psk) == 0 || len(salt) != nativeUDPSaltLength || len(exporter) != nativeUDPExporterLength {
		return nativeUDPAuthorization{}, errors.New("artx: invalid native UDP authorization input")
	}
	if err := request.validate(); err != nil {
		return nativeUDPAuthorization{}, err
	}
	authorization := nativeUDPAuthorization{locator: calculateUserLocator(psk), bucket: bucket}
	copy(authorization.salt[:], salt)
	tag, err := nativeUDPClientTag(psk, exporter, request, authorization.prefix())
	if err != nil {
		return nativeUDPAuthorization{}, err
	}
	authorization.clientTag = tag
	return authorization, nil
}

func (authorization nativeUDPAuthorization) header() string {
	return "ArtX " + base64.RawURLEncoding.EncodeToString(append(authorization.prefix(), authorization.clientTag[:]...))
}

func (authorization nativeUDPAuthorization) verifyServerProof(header string, psk, exporter []byte, status int, capsuleProtocol string) bool {
	const prefix = `rspauth="`
	if !strings.HasPrefix(header, prefix) || !strings.HasSuffix(header, `"`) {
		return false
	}
	encoded := header[len(prefix) : len(header)-1]
	if len(encoded) != base64.RawURLEncoding.EncodedLen(nativeUDPTagLength) {
		return false
	}
	proof, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(proof) != encoded {
		return false
	}
	want, err := nativeUDPServerProof(psk, exporter, authorization.clientTag, status, capsuleProtocol)
	return err == nil && hmac.Equal(proof, want[:])
}

func (authorization nativeUDPAuthorization) prefix() []byte {
	prefix := make([]byte, nativeUDPAuthPrefixSize)
	prefix[0], prefix[1] = nativeUDPAuthVersion, nativeUDPAuthFlags
	offset := 2
	copy(prefix[offset:], authorization.salt[:])
	offset += nativeUDPSaltLength
	copy(prefix[offset:], authorization.locator[:])
	offset += len(authorization.locator)
	binary.BigEndian.PutUint32(prefix[offset:], authorization.bucket)
	return prefix
}

func (request nativeUDPRequest) validate() error {
	if request.method != "CONNECT" || request.protocol != "connect-udp" || request.scheme != "https" ||
		request.authority == "" || request.path == "" || request.capsuleProtocol != "?1" {
		return errors.New("artx: invalid native UDP request")
	}
	for _, value := range []string{request.authority, request.method, request.protocol, request.path} {
		if len(value) > int(^uint16(0)) {
			return errors.New("artx: native UDP authentication field too long")
		}
	}
	return nil
}

func nativeUDPClientTag(psk, exporter []byte, request nativeUDPRequest, prefix []byte) ([nativeUDPTagLength]byte, error) {
	if len(psk) == 0 || len(exporter) != nativeUDPExporterLength {
		return [nativeUDPTagLength]byte{}, errors.New("artx: invalid native UDP client tag input")
	}
	if err := request.validate(); err != nil {
		return [nativeUDPTagLength]byte{}, err
	}
	mac := hmac.New(sha256.New, psk)
	_, _ = mac.Write([]byte(nativeUDPClientLabel))
	_, _ = mac.Write(exporter)
	for _, value := range []string{request.authority, request.method, request.protocol, request.path} {
		if err := writeNativeUDPLengthPrefixed(mac, value); err != nil {
			return [nativeUDPTagLength]byte{}, err
		}
	}
	_, _ = mac.Write(prefix)
	var tag [nativeUDPTagLength]byte
	copy(tag[:], mac.Sum(nil))
	return tag, nil
}

func nativeUDPServerProof(psk, exporter []byte, clientTag [nativeUDPTagLength]byte, status int, capsuleProtocol string) ([nativeUDPTagLength]byte, error) {
	if len(psk) == 0 || len(exporter) != nativeUDPExporterLength || status < 100 || status > 999 {
		return [nativeUDPTagLength]byte{}, errors.New("artx: invalid native UDP server proof input")
	}
	mac := hmac.New(sha256.New, psk)
	_, _ = mac.Write([]byte(nativeUDPServerLabel))
	_, _ = mac.Write(exporter)
	_, _ = mac.Write(clientTag[:])
	var encodedStatus [2]byte
	binary.BigEndian.PutUint16(encodedStatus[:], uint16(status))
	_, _ = mac.Write(encodedStatus[:])
	if err := writeNativeUDPLengthPrefixed(mac, capsuleProtocol); err != nil {
		return [nativeUDPTagLength]byte{}, err
	}
	var proof [nativeUDPTagLength]byte
	copy(proof[:], mac.Sum(nil))
	return proof, nil
}

func writeNativeUDPLengthPrefixed(writer hash.Hash, value string) error {
	if len(value) > int(^uint16(0)) {
		return fmt.Errorf("artx: native UDP field length %d exceeds limit", len(value))
	}
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(value)))
	_, _ = writer.Write(length[:])
	_, _ = writer.Write([]byte(value))
	return nil
}
