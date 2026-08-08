package naive

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/vmess"

	"github.com/metacubex/http"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
	"github.com/metacubex/tls"
)

// naiveH3TestServer answers CONNECT over HTTP/3 the way sing-box's naive
// inbound does: it demands the padding and authorization headers, then relays
// the tunnel on the QUIC stream behind the request body and response writer.
type naiveH3TestServer struct {
	server      *http3.Server
	packetConn  net.PacketConn
	username    string
	password    string
	sendPadding bool

	mu                sync.Mutex
	observedAuthority string
	observedPadding   string
	observedHeader    http.Header
	observedEOF       bool
}

func newNaiveH3TestServer(t *testing.T, username, password string, sendPadding bool) *naiveH3TestServer {
	t.Helper()
	packetConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	der, key := selfSignedCertificateMaterial(t)
	server := &naiveH3TestServer{
		packetConn:  packetConn,
		username:    username,
		password:    password,
		sendPadding: sendPadding,
	}
	server.server = &http3.Server{
		Handler: server,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
			NextProtos:   []string{http3.NextProtoH3},
		},
	}
	go func() { _ = server.server.Serve(packetConn) }()
	t.Cleanup(func() {
		_ = server.server.Close()
		_ = packetConn.Close()
	})
	return server
}

func (server *naiveH3TestServer) address() net.Addr {
	return server.packetConn.LocalAddr()
}

func (server *naiveH3TestServer) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
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
func (server *naiveH3TestServer) echo(body io.Reader, writer io.Writer) {
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

func (server *naiveH3TestServer) authority() string {
	server.mu.Lock()
	defer server.mu.Unlock()
	return server.observedAuthority
}

func (server *naiveH3TestServer) requestPadding() string {
	server.mu.Lock()
	defer server.mu.Unlock()
	return server.observedPadding
}

func (server *naiveH3TestServer) requestHeader() http.Header {
	server.mu.Lock()
	defer server.mu.Unlock()
	return server.observedHeader
}

func (server *naiveH3TestServer) sawEOF() bool {
	server.mu.Lock()
	defer server.mu.Unlock()
	return server.observedEOF
}

func testH3ClientConfig(username, password string) ClientConfig {
	return ClientConfig{
		Username: username,
		Password: password,
		TLSConfig: &vmess.TLSConfig{
			Host:              "naive.test",
			SkipCertVerify:    true,
			ClientFingerprint: "chrome",
		},
	}
}

// dialTestQUICConnection brings up the QUIC connection the outbound would
// normally hand to DialH3Context, plus the cleanup that owns it.
func dialTestQUICConnection(t *testing.T, server *naiveH3TestServer) (*quic.Conn, func() error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)

	tlsConfig, err := PrepareH3TLS(ctx, testH3ClientConfig("", ""))
	if err != nil {
		t.Fatal(err)
	}
	packetConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		t.Fatal(err)
	}
	transport := &quic.Transport{Conn: packetConn}
	quicConnection, err := transport.Dial(ctx, server.address(), tlsConfig, &quic.Config{})
	if err != nil {
		_ = packetConn.Close()
		t.Fatal(err)
	}
	return quicConnection, func() error {
		return errors.Join(quicConnection.CloseWithError(0, ""), packetConn.Close())
	}
}

func dialTestH3Tunnel(t *testing.T, server *naiveH3TestServer, username, password, destination string) (net.Conn, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)

	quicConnection, closeTransport := dialTestQUICConnection(t, server)
	tunnel, err := DialH3Context(ctx, quicConnection, testH3ClientConfig(username, password), destination, closeTransport)
	if err != nil {
		_ = closeTransport()
		return nil, err
	}
	return tunnel, nil
}

func TestDialH3ContextTunnelsThroughNaiveServer(t *testing.T) {
	server := newNaiveH3TestServer(t, "user", "secret", true)
	tunnel, err := dialTestH3Tunnel(t, server, "user", "secret", "example.com:443")
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
func TestDialH3ContextSendsNoClientHeaders(t *testing.T) {
	server := newNaiveH3TestServer(t, "user", "secret", true)
	tunnel, err := dialTestH3Tunnel(t, server, "user", "secret", "example.com:443")
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

func TestDialH3ContextHalfClosesOnCloseWrite(t *testing.T) {
	server := newNaiveH3TestServer(t, "user", "secret", true)
	tunnel, err := dialTestH3Tunnel(t, server, "user", "secret", "example.com:443")
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
	deadline := time.Now().Add(10 * time.Second)
	for !server.sawEOF() {
		if time.Now().After(deadline) {
			t.Fatal("the server never saw the half-close")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestDialH3ContextRejectsBadCredentials(t *testing.T) {
	server := newNaiveH3TestServer(t, "user", "secret", true)
	tunnel, err := dialTestH3Tunnel(t, server, "user", "wrong", "example.com:443")
	if err == nil {
		tunnel.Close()
		t.Fatal("a rejected credential must fail the dial")
	}
	if !strings.Contains(err.Error(), "credentials") {
		t.Fatalf("got %v, want an error naming the credentials", err)
	}
}

func TestDialH3ContextWithoutPaddingNegotiation(t *testing.T) {
	server := newNaiveH3TestServer(t, "user", "secret", false)
	tunnel, err := dialTestH3Tunnel(t, server, "user", "secret", "example.com:443")
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

// The tunnel owns the QUIC connection it was handed, so closing it has to
// release the socket too — otherwise every dial leaks one.
func TestDialH3ContextCloseReleasesTheTransport(t *testing.T) {
	server := newNaiveH3TestServer(t, "user", "secret", true)
	tunnel, err := dialTestH3Tunnel(t, server, "user", "secret", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	if err := tunnel.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := tunnel.Close(); err != nil {
		t.Fatalf("a second close must be a no-op, got %v", err)
	}
	if _, err := tunnel.Write([]byte("after close")); err == nil {
		t.Fatal("writing to a closed tunnel must fail")
	}
}

func TestDialH3ContextValidatesArguments(t *testing.T) {
	noop := func() error { return nil }
	// Every guard returns before the connection is touched, so one live QUIC
	// connection covers the cases that need a non-nil one.
	server := newNaiveH3TestServer(t, "user", "secret", true)
	live, closeLive := dialTestQUICConnection(t, server)
	t.Cleanup(func() { _ = closeLive() })

	tests := []struct {
		name           string
		connection     *quic.Conn
		closeTransport func() error
		destination    string
		want           string
	}{
		{name: "missing connection", closeTransport: noop, destination: "example.com:443", want: "QUIC connection"},
		{name: "missing cleanup", connection: live, destination: "example.com:443", want: "cleanup function"},
		{name: "missing destination", connection: live, closeTransport: noop, want: "destination authority"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := DialH3Context(context.Background(), test.connection, ClientConfig{}, test.destination, test.closeTransport)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("got %v, want an error mentioning %q", err, test.want)
			}
		})
	}
}

func TestPrepareH3TLS(t *testing.T) {
	config := testH3ClientConfig("user", "secret")
	tlsConfig, err := PrepareH3TLS(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	if got := tlsConfig.NextProtos; len(got) != 1 || got[0] != http3.NextProtoH3 {
		t.Fatalf("ALPN is %v, want [%s]", got, http3.NextProtoH3)
	}
	// QUIC has no TLS below 1.3, and pinning both ends keeps a profile from
	// asking for something the handshake cannot deliver.
	if tlsConfig.MinVersion != tls.VersionTLS13 || tlsConfig.MaxVersion != tls.VersionTLS13 {
		t.Fatalf("TLS versions are [%x, %x], want TLS 1.3 only", tlsConfig.MinVersion, tlsConfig.MaxVersion)
	}
	if tlsConfig.ServerName != "naive.test" {
		t.Fatalf("SNI is %q, want the configured host", tlsConfig.ServerName)
	}
}

// A server that publishes something other than h3 — sing-box's naive inbound
// currently advertises the TCP ALPN on its QUIC listener too — is reachable by
// naming its ALPN in the profile.
func TestPrepareH3TLSKeepsAnExplicitALPN(t *testing.T) {
	config := testH3ClientConfig("user", "secret")
	config.TLSConfig.NextProtos = []string{"h2"}
	tlsConfig, err := PrepareH3TLS(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	if got := tlsConfig.NextProtos; len(got) != 1 || got[0] != "h2" {
		t.Fatalf("ALPN is %v, want the configured one", got)
	}
}

func TestPrepareH3TLSRequiresATLSConfig(t *testing.T) {
	if _, err := PrepareH3TLS(context.Background(), ClientConfig{}); err == nil {
		t.Fatal("expected an error")
	} else if !strings.Contains(err.Error(), "TLS configuration") {
		t.Fatalf("got %v, want an error mentioning the TLS configuration", err)
	}
}
