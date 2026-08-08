package artx

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	tlsC "github.com/metacubex/mihomo/component/tls"
	"github.com/metacubex/mihomo/transport/vmess"
	"github.com/metacubex/sing/common"
	"github.com/metacubex/sing/common/network"
	"github.com/metacubex/tls"
)

const (
	wireV4VectorClientInit         = "0400101112131415161718191a1b1c1d1e1f4a94d7419f1832b4010203049e5af74154d3dd14e66ffd749476f37f42e62a357d1a88a16b41d6f6e0f36044"
	wireV4VectorProxyAuthorization = "Bearer BAAQERITFBUWFxgZGhscHR4fSpTXQZ8YMrQBAgMEnlr3QVTT3RTmb_10lHbzf0LmKjV9Goiha0HW9uDzYEQ"
	wireV4VectorAuthenticationInfo = "rspauth=\"Dis5apxthZBnnww8x6WE1fFBmuF1qZlQmJzInwv2xRY\""
)

func TestWireV4CanonicalVector(t *testing.T) {
	psk, exporter, salt := wireV4VectorInputs()
	init, err := newWireV4ClientInit(psk, salt, exporter, "example.com", "example.net:443", 0x01020304)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := init.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(envelope); got != wireV4VectorClientInit {
		t.Fatalf("ClientInit = %s", got)
	}
	if got := formatWireV4ProxyAuthorization(init); got != wireV4VectorProxyAuthorization {
		t.Fatalf("Proxy-Authorization = %q", got)
	}
	parsed, candidate, err := parseWireV4ProxyAuthorization(wireV4VectorProxyAuthorization)
	if err != nil || !candidate {
		t.Fatalf("parse candidate = %v, %v", candidate, err)
	}
	if !parsed.Verify(psk, exporter, "example.com", "example.net:443") {
		t.Fatal("canonical ClientInit did not verify")
	}
	proof := calculateWireV4ServerProof(psk, exporter, parsed.ClientTag, 200)
	if got := formatWireV4ProxyAuthenticationInfo(proof); got != wireV4VectorAuthenticationInfo {
		t.Fatalf("Proxy-Authentication-Info = %q", got)
	}
	if !verifyWireV4ProxyAuthenticationInfo(wireV4VectorAuthenticationInfo, psk, exporter, parsed.ClientTag, 200) {
		t.Fatal("canonical ServerProof did not verify")
	}
}

func TestWireV4VectorBindings(t *testing.T) {
	psk, exporter, _ := wireV4VectorInputs()
	parsed, candidate, err := parseWireV4ProxyAuthorization(wireV4VectorProxyAuthorization)
	if err != nil || !candidate {
		t.Fatal(err)
	}
	for name, context := range map[string][2]string{
		"server name": {"other.example", "example.net:443"},
		"target":      {"example.com", "example.net:8443"},
	} {
		t.Run(name, func(t *testing.T) {
			if parsed.Verify(psk, exporter, context[0], context[1]) {
				t.Fatal("changed context verified")
			}
		})
	}
	if verifyWireV4ProxyAuthenticationInfo(wireV4VectorAuthenticationInfo, psk, exporter, parsed.ClientTag, 502) {
		t.Fatal("proof verified for changed status")
	}
}

func TestWireV4CanonicalAuthority(t *testing.T) {
	tests := []struct {
		name      string
		authority string
		want      Destination
		valid     bool
	}{
		{name: "domain", authority: "example.net:443", want: Destination{Host: "example.net", Port: 443}, valid: true},
		{name: "IPv4", authority: "192.0.2.1:80", want: Destination{IP: netip.MustParseAddr("192.0.2.1"), Port: 80}, valid: true},
		{name: "IPv6", authority: "[2001:db8::1]:8443", want: Destination{IP: netip.MustParseAddr("2001:db8::1"), Port: 8443}, valid: true},
		{name: "upper case", authority: "Example.net:443"},
		{name: "leading zero port", authority: "example.net:0443"},
		{name: "path", authority: "example.net:443/path"},
		{name: "userinfo", authority: "user@example.net:443"},
		{name: "unbracketed IPv6", authority: "2001:db8::1:443"},
		{name: "IPv6 zone", authority: "[fe80::1%en0]:443"},
		{name: "empty port", authority: "example.net:"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseWireV4Authority(test.authority)
			if !test.valid {
				if err == nil {
					t.Fatalf("accepted %#v", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("destination = %#v, want %#v", got, test.want)
			}
			canonical, err := formatWireV4Authority(got)
			if err != nil || canonical != test.authority {
				t.Fatalf("round trip = %q, %v", canonical, err)
			}
		})
	}
}

func TestWireV4RejectsIPServerName(t *testing.T) {
	psk, exporter, salt := wireV4VectorInputs()
	if _, err := newWireV4ClientInit(psk, salt, exporter, "127.0.0.1", "example.net:443", 1); err == nil {
		t.Fatal("accepted IP literal as wire-v4 server name")
	}
}

func TestWireV4HandshakeContextDoesNotExposeAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := finishWireV4HandshakeContext(ctx, func() bool { return true }); !errors.Is(err, context.Canceled) {
		t.Fatalf("finish error = %v, want context cancellation", err)
	}
}

func TestWireV4HTTP1TunnelPreservesBufferedServerFirstAndUploadHalfClose(t *testing.T) {
	clientRaw, serverRaw := net.Pipe()
	serverDone := make(chan error, 1)
	serverConfig := wireV4TestServerConfig(t)
	go func() { serverDone <- runWireV4HTTP1TestServer(serverRaw, serverConfig, wireV4TestUploadHalfClose) }()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	connection, err := DialContext(ctx, clientRaw, wireV4TestClientConfig(), Destination{Host: "example.net", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()

	serverFirst := make([]byte, len("server-first"))
	if _, err := io.ReadFull(connection, serverFirst); err != nil {
		t.Fatal(err)
	}
	if string(serverFirst) != "server-first" {
		t.Fatalf("server-first = %q", serverFirst)
	}
	if _, err := connection.Write([]byte("client-upload")); err != nil {
		t.Fatal(err)
	}
	if err := closeWireV4TestWrite(connection); err != nil {
		t.Fatal(err)
	}
	afterEOF := make([]byte, len("after-upload-eof"))
	if _, err := io.ReadFull(connection, afterEOF); err != nil {
		t.Fatal(err)
	}
	if string(afterEOF) != "after-upload-eof" {
		t.Fatalf("response after upload EOF = %q", afterEOF)
	}
	if _, err := connection.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("read after server CloseWrite = %v, want EOF", err)
	}
	waitWireV4TestServer(t, serverDone)
}

func TestWireV4TargetDownloadHalfCloseKeepsUploadWritable(t *testing.T) {
	clientRaw, serverRaw := net.Pipe()
	serverDone := make(chan error, 1)
	serverConfig := wireV4TestServerConfig(t)
	go func() { serverDone <- runWireV4HTTP1TestServer(serverRaw, serverConfig, wireV4TestDownloadHalfClose) }()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	connection, err := DialContext(ctx, clientRaw, wireV4TestClientConfig(), Destination{Host: "example.net", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()

	downlink := make([]byte, len("target-eof"))
	if _, err := io.ReadFull(connection, downlink); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("target half-close = %v, want EOF", err)
	}
	if _, err := connection.Write([]byte("late-upload")); err != nil {
		t.Fatalf("upload after target EOF: %v", err)
	}
	if err := closeWireV4TestWrite(connection); err != nil {
		t.Fatal(err)
	}
	waitWireV4TestServer(t, serverDone)
}

func TestWireV4ClientRejectsWrongProofBeforeExposure(t *testing.T) {
	clientRaw, serverRaw := net.Pipe()
	serverDone := make(chan error, 1)
	serverConfig := wireV4TestServerConfig(t)
	go func() { serverDone <- runWireV4HTTP1TestServer(serverRaw, serverConfig, wireV4TestWrongProof) }()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	connection, err := DialContext(ctx, clientRaw, wireV4TestClientConfig(), Destination{Host: "example.net", Port: 443})
	if err == nil || connection != nil {
		t.Fatal("wire-v4 client exposed a connection with the wrong proof")
	}
	waitWireV4TestServer(t, serverDone)
}

func TestWireV4ClientRejectsResponseFramingBeforeExposure(t *testing.T) {
	clientRaw, serverRaw := net.Pipe()
	serverDone := make(chan error, 1)
	serverConfig := wireV4TestServerConfig(t)
	go func() { serverDone <- runWireV4HTTP1TestServer(serverRaw, serverConfig, wireV4TestContentLength) }()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	connection, err := DialContext(ctx, clientRaw, wireV4TestClientConfig(), Destination{Host: "example.net", Port: 443})
	if err == nil || connection != nil {
		t.Fatal("wire-v4 client exposed a response with Content-Length")
	}
	waitWireV4TestServer(t, serverDone)
}

func TestWireV4ClientRejectsAuthenticationChallengeBeforeExposure(t *testing.T) {
	clientRaw, serverRaw := net.Pipe()
	serverDone := make(chan error, 1)
	serverConfig := wireV4TestServerConfig(t)
	go func() {
		serverDone <- runWireV4HTTP1TestServer(serverRaw, serverConfig, wireV4TestAuthenticationChallenge)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	connection, err := DialContext(ctx, clientRaw, wireV4TestClientConfig(), Destination{Host: "example.net", Port: 443})
	if err == nil || connection != nil {
		t.Fatal("wire-v4 client exposed a response with WWW-Authenticate")
	}
	waitWireV4TestServer(t, serverDone)
}

type wireV4TestMode byte

const (
	wireV4TestUploadHalfClose wireV4TestMode = iota
	wireV4TestDownloadHalfClose
	wireV4TestWrongProof
	wireV4TestContentLength
	wireV4TestAuthenticationChallenge
)

func wireV4TestClientConfig() ClientConfig {
	return ClientConfig{
		Password:       "secret",
		Profile:        "balanced",
		ProfileVersion: 1,
		WireVersion:    4,
		Authority:      "example.com",
		TLSConfig: &vmess.TLSConfig{
			Host:              "example.com",
			SkipCertVerify:    true,
			ClientFingerprint: "chrome",
		},
	}
}

func wireV4TestServerConfig(t *testing.T) *tls.Config {
	t.Helper()
	config := testTLSConfig(t, tls.VersionTLS13, tls.VersionTLS13)
	config.NextProtos = []string{"http/1.1"}
	return config
}

func runWireV4HTTP1TestServer(raw net.Conn, config *tls.Config, mode wireV4TestMode) error {
	defer raw.Close()
	connection := tls.Server(raw, config)
	if err := connection.Handshake(); err != nil {
		return err
	}
	state := tlsC.GetTLSConnectionState(connection)
	if state.NegotiatedProtocol != "http/1.1" || state.DidResume {
		return errors.New("wire-v4 test client did not negotiate fresh HTTP/1.1")
	}
	exporter, err := state.ExportKeyingMaterial(wireV4ExporterLabel, nil, wireV4ExporterLength)
	if err != nil {
		return err
	}
	reader := bufio.NewReader(connection)
	request, err := http.ReadRequest(reader)
	if err != nil {
		return err
	}
	defer request.Body.Close()
	if request.Method != http.MethodConnect || request.RequestURI != "example.net:443" || request.Host != "example.net:443" || request.URL.Host != "example.net:443" {
		return fmt.Errorf("unexpected CONNECT request: method=%q uri=%q host=%q url=%q", request.Method, request.RequestURI, request.Host, request.URL.Host)
	}
	if request.UserAgent() != "" || request.ContentLength != 0 || len(request.TransferEncoding) != 0 || reader.Buffered() != 0 {
		return errors.New("wire-v4 CONNECT carried forbidden headers, body, or early data")
	}
	init, candidate, err := parseWireV4ProxyAuthorization(request.Header.Get("Proxy-Authorization"))
	if err != nil || !candidate || len(request.Header.Values("Proxy-Authorization")) != 1 || !init.Verify([]byte("secret"), exporter, "example.com", request.RequestURI) {
		return errors.New("invalid wire-v4 ClientInit")
	}
	proof := calculateWireV4ServerProof([]byte("secret"), exporter, init.ClientTag, http.StatusOK)
	if mode == wireV4TestWrongProof {
		proof[0] ^= 1
	}
	extraHeader := ""
	if mode == wireV4TestContentLength {
		extraHeader = "Content-Length: 0\r\n"
	}
	if mode == wireV4TestAuthenticationChallenge {
		extraHeader = "WWW-Authenticate: Basic realm=\"decoy\"\r\n"
	}
	response := fmt.Sprintf("HTTP/1.1 200 Connection Established\r\nProxy-Authentication-Info: %s\r\nCache-Control: no-store\r\n%s\r\n", formatWireV4ProxyAuthenticationInfo(proof), extraHeader)
	initial := "server-first"
	if mode == wireV4TestDownloadHalfClose {
		initial = "target-eof"
	}
	if err := writeFull(connection, append([]byte(response), []byte(initial)...)); err != nil {
		return err
	}
	if mode == wireV4TestWrongProof || mode == wireV4TestContentLength || mode == wireV4TestAuthenticationChallenge {
		return nil
	}
	if mode == wireV4TestDownloadHalfClose {
		if err := connection.CloseWrite(); err != nil {
			return err
		}
		upload, err := io.ReadAll(connection)
		if err != nil {
			return err
		}
		if string(upload) != "late-upload" {
			return fmt.Errorf("late upload = %q", upload)
		}
		return nil
	}
	upload, err := io.ReadAll(connection)
	if err != nil {
		return err
	}
	if string(upload) != "client-upload" {
		return fmt.Errorf("upload = %q", upload)
	}
	if err := writeFull(connection, []byte("after-upload-eof")); err != nil {
		return err
	}
	return connection.CloseWrite()
}

func waitWireV4TestServer(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("wire-v4 test server did not close")
	}
}

func closeWireV4TestWrite(connection net.Conn) error {
	closer, ok := common.Cast[network.WriteCloser](connection)
	if !ok {
		return errors.New("wire-v4 connection has no CloseWrite path")
	}
	return closer.CloseWrite()
}

func wireV4VectorInputs() ([]byte, []byte, []byte) {
	exporter := make([]byte, wireV4ExporterLength)
	for index := range exporter {
		exporter[index] = byte(index)
	}
	salt := make([]byte, wireV4SaltLength)
	for index := range salt {
		salt[index] = byte(0x10 + index)
	}
	return []byte("test-psk"), exporter, salt
}
