package naive

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/vmess"

	"golang.org/x/net/http2"
)

// naiveTestServer answers CONNECT the way a naive server does — it demands the
// padding and authorization headers, then echoes the tunnel back — so the
// client is exercised against the handshake it will meet in production.
type naiveTestServer struct {
	listener    net.Listener
	username    string
	password    string
	sendPadding bool

	mu                sync.Mutex
	observedAuthority string
	observedPadding   string
	observedHeader    http.Header
	observedEOF       bool
}

func newNaiveTestServer(t *testing.T, username, password string, sendPadding bool, alpn []string) *naiveTestServer {
	t.Helper()
	rawListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &naiveTestServer{
		listener:    tls.NewListener(rawListener, &tls.Config{Certificates: []tls.Certificate{selfSignedCertificate(t)}, NextProtos: alpn}),
		username:    username,
		password:    password,
		sendPadding: sendPadding,
	}
	go server.serve()
	t.Cleanup(func() { _ = server.listener.Close() })
	return server
}

func (server *naiveTestServer) address() string {
	return server.listener.Addr().String()
}

func (server *naiveTestServer) serve() {
	http2Server := &http2.Server{}
	for {
		connection, err := server.listener.Accept()
		if err != nil {
			return
		}
		go func() {
			defer connection.Close()
			if tlsConnection, ok := connection.(*tls.Conn); ok {
				if err := tlsConnection.Handshake(); err != nil {
					return
				}
				if tlsConnection.ConnectionState().NegotiatedProtocol != http2.NextProtoTLS {
					return
				}
			}
			http2Server.ServeConn(connection, &http2.ServeConnOpts{Handler: server})
		}()
	}
}

func (server *naiveTestServer) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodConnect {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	padding := request.Header.Get(paddingHeader)
	if padding == "" {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	username, password, ok := parseBasicProxyAuth(request.Header.Get("Proxy-Authorization"))
	if !ok || username != server.username || password != server.password {
		writer.WriteHeader(http.StatusProxyAuthRequired)
		return
	}

	server.mu.Lock()
	server.observedAuthority = request.Host
	server.observedPadding = padding
	server.observedHeader = request.Header.Clone()
	server.mu.Unlock()

	if server.sendPadding {
		writer.Header().Set(paddingHeader, generateHeaderPadding())
	}
	writer.WriteHeader(http.StatusOK)
	flusher := writer.(http.Flusher)
	flusher.Flush()
	server.echo(request.Body, flushingWriter{writer: writer, flusher: flusher})
}

// echo mirrors the tunnel back through the same padding scheme the client uses.
func (server *naiveTestServer) echo(body io.Reader, writer io.Writer) {
	state := newPaddingState(server.sendPadding)
	buffer := make([]byte, 4096)
	for {
		read, err := state.readWithPadding(body, buffer)
		if read > 0 {
			if _, writeErr := state.writeWithPadding(writer, buffer[:read]); writeErr != nil {
				return
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				server.mu.Lock()
				server.observedEOF = true
				server.mu.Unlock()
			}
			return
		}
	}
}

func (server *naiveTestServer) authority() string {
	server.mu.Lock()
	defer server.mu.Unlock()
	return server.observedAuthority
}

func (server *naiveTestServer) requestPadding() string {
	server.mu.Lock()
	defer server.mu.Unlock()
	return server.observedPadding
}

func (server *naiveTestServer) requestHeader() http.Header {
	server.mu.Lock()
	defer server.mu.Unlock()
	return server.observedHeader
}

func (server *naiveTestServer) sawEOF() bool {
	server.mu.Lock()
	defer server.mu.Unlock()
	return server.observedEOF
}

// flusher is spelled out rather than taken from net/http so the HTTP/3 tests,
// whose stack speaks a different http package, can reuse this writer.
type flushingWriter struct {
	writer  io.Writer
	flusher interface{ Flush() }
}

func (writer flushingWriter) Write(payload []byte) (int, error) {
	written, err := writer.writer.Write(payload)
	if err == nil {
		writer.flusher.Flush()
	}
	return written, err
}

func parseBasicProxyAuth(header string) (username, password string, ok bool) {
	const prefix = "Basic "
	if !strings.HasPrefix(header, prefix) {
		return "", "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(header, prefix))
	if err != nil {
		return "", "", false
	}
	username, password, found := strings.Cut(string(decoded), ":")
	return username, password, found
}

func selfSignedCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	der, key := selfSignedCertificateMaterial(t)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// selfSignedCertificateMaterial hands back the raw pieces so both TLS packages
// in play — crypto/tls here, metacubex/tls under QUIC — can build their own
// certificate from one implementation.
func selfSignedCertificateMaterial(t *testing.T) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "naive.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"naive.test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der, key
}

func dialTestTunnel(t *testing.T, server *naiveTestServer, username, password, destination string) (net.Conn, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", server.address())
	if err != nil {
		t.Fatal(err)
	}
	return DialContext(ctx, raw, ClientConfig{
		Username: username,
		Password: password,
		TLSConfig: &vmess.TLSConfig{
			Host:              "naive.test",
			SkipCertVerify:    true,
			ClientFingerprint: "chrome",
		},
	}, destination)
}

func TestDialContextTunnelsThroughNaiveServer(t *testing.T) {
	server := newNaiveTestServer(t, "user", "secret", true, []string{http2.NextProtoTLS, alpnHTTP11})
	tunnel, err := dialTestTunnel(t, server, "user", "secret", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	defer tunnel.Close()

	// More rounds than the padding budget, so the switch to verbatim framing is
	// covered in both directions.
	for round := 0; round < paddedFrameCount+3; round++ {
		payload := bytes.Repeat([]byte{byte('a' + round)}, 128+round)
		if _, err := tunnel.Write(payload); err != nil {
			t.Fatalf("round %d write: %v", round, err)
		}
		echoed := make([]byte, len(payload))
		if _, err := io.ReadFull(tunnel, echoed); err != nil {
			t.Fatalf("round %d read: %v", round, err)
		}
		if !bytes.Equal(echoed, payload) {
			t.Fatalf("round %d echoed %q, want %q", round, echoed, payload)
		}
	}

	if authority := server.authority(); authority != "example.com:443" {
		t.Fatalf("server saw :authority %q, want %q", authority, "example.com:443")
	}
	padding := server.requestPadding()
	if len(padding) < minHeaderPaddingSize || len(padding) > maxHeaderPaddingSize {
		t.Fatalf("server saw a %d byte padding header, want [%d, %d]", len(padding), minHeaderPaddingSize, maxHeaderPaddingSize)
	}
}

// A CONNECT that announces a Go client or asks for gzip does not look like the
// Chrome request naive exists to imitate.
func TestDialContextSendsNoClientHeaders(t *testing.T) {
	server := newNaiveTestServer(t, "user", "secret", true, []string{http2.NextProtoTLS, alpnHTTP11})
	tunnel, err := dialTestTunnel(t, server, "user", "secret", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	defer tunnel.Close()

	header := server.requestHeader()
	for _, name := range []string{"User-Agent", "Accept-Encoding"} {
		if value := header.Get(name); value != "" {
			t.Fatalf("the server saw %s: %q, want it omitted", name, value)
		}
	}
}

func TestDialContextHalfClosesOnCloseWrite(t *testing.T) {
	server := newNaiveTestServer(t, "user", "secret", true, []string{http2.NextProtoTLS, alpnHTTP11})
	tunnel, err := dialTestTunnel(t, server, "user", "secret", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	defer tunnel.Close()

	if _, err := tunnel.Write([]byte("last")); err != nil {
		t.Fatal(err)
	}
	echoed := make([]byte, 4)
	if _, err := io.ReadFull(tunnel, echoed); err != nil {
		t.Fatal(err)
	}
	closeWriter, ok := tunnel.(interface{ CloseWrite() error })
	if !ok {
		t.Fatal("the tunnel must expose CloseWrite for half-close relaying")
	}
	if err := closeWriter.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for !server.sawEOF() {
		if time.Now().After(deadline) {
			t.Fatal("the server never saw the half-close")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestDialContextRejectsBadCredentials(t *testing.T) {
	server := newNaiveTestServer(t, "user", "secret", true, []string{http2.NextProtoTLS, alpnHTTP11})
	tunnel, err := dialTestTunnel(t, server, "user", "wrong", "example.com:443")
	if err == nil {
		tunnel.Close()
		t.Fatal("a rejected credential must fail the dial")
	}
	if !strings.Contains(err.Error(), "credentials") {
		t.Fatalf("got %v, want an error naming the credentials", err)
	}
}

func TestDialContextWithoutPaddingNegotiation(t *testing.T) {
	server := newNaiveTestServer(t, "user", "secret", false, []string{http2.NextProtoTLS, alpnHTTP11})
	tunnel, err := dialTestTunnel(t, server, "user", "secret", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	defer tunnel.Close()

	if _, err := tunnel.Write([]byte("verbatim")); err != nil {
		t.Fatal(err)
	}
	echoed := make([]byte, len("verbatim"))
	if _, err := io.ReadFull(tunnel, echoed); err != nil {
		t.Fatal(err)
	}
	if string(echoed) != "verbatim" {
		t.Fatalf("echoed %q, want %q", echoed, "verbatim")
	}
}

func TestDialContextRequiresH2ALPN(t *testing.T) {
	server := newNaiveTestServer(t, "user", "secret", true, []string{alpnHTTP11})
	tunnel, err := dialTestTunnel(t, server, "user", "secret", "example.com:443")
	if err == nil {
		tunnel.Close()
		t.Fatal("a server without h2 must fail the dial")
	}
	if !strings.Contains(err.Error(), "ALPN") {
		t.Fatalf("got %v, want an error naming the ALPN mismatch", err)
	}
}

func TestDialContextValidatesArguments(t *testing.T) {
	tests := []struct {
		name        string
		config      ClientConfig
		destination string
		want        string
	}{
		{
			name:        "missing tls config",
			config:      ClientConfig{},
			destination: "example.com:443",
			want:        "TLS configuration",
		},
		{
			name:        "missing destination",
			config:      ClientConfig{TLSConfig: &vmess.TLSConfig{Host: "naive.test"}},
			destination: "",
			want:        "destination authority",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer server.Close()
			if _, err := DialContext(context.Background(), client, test.config, test.destination); err == nil {
				t.Fatal("expected an error")
			} else if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("got %v, want an error mentioning %q", err, test.want)
			}
		})
	}
}
