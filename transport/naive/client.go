package naive

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"

	tlsC "github.com/metacubex/mihomo/component/tls"
	"github.com/metacubex/mihomo/transport/vmess"

	"golang.org/x/net/http2"
)

const (
	// paddingHeader is the header both peers use to offer and to accept the
	// padding scheme.
	paddingHeader = "Padding"
	// alpnHTTP11 is offered alongside h2 because Chrome offers both, and this
	// transport is only worth using with a Chrome-shaped ClientHello.
	alpnHTTP11 = "http/1.1"
)

// ClientConfig carries what the CONNECT handshake needs beyond the destination.
type ClientConfig struct {
	Username     string
	Password     string
	ExtraHeaders map[string]string
	TLSConfig    *vmess.TLSConfig
}

// DialContext performs the naive handshake over raw and returns the tunnel as
// a net.Conn. destination is the target authority in host:port form. raw is
// closed when the handshake fails; on success the returned connection owns it.
func DialContext(ctx context.Context, raw net.Conn, config ClientConfig, destination string) (_ net.Conn, err error) {
	if config.TLSConfig == nil {
		return nil, errors.New("naive requires a TLS configuration")
	}
	if destination == "" {
		return nil, errors.New("naive requires a destination authority")
	}
	defer func() {
		if err != nil {
			_ = raw.Close()
		}
	}()
	// ctx covers the handshake only. An established tunnel outlives the dial,
	// so it gets its own context below rather than dying with this one.
	stopOnContextDone := context.AfterFunc(ctx, func() { _ = raw.Close() })
	defer stopOnContextDone()

	tlsConnection, err := handshakeTLS(ctx, raw, config)
	if err != nil {
		return nil, err
	}
	clientConnection, err := new(http2.Transport).NewClientConn(tlsConnection)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = clientConnection.Close()
		}
	}()

	tunnelCtx, cancelTunnel := context.WithCancel(context.Background())
	uploadReader, uploadWriter := io.Pipe()
	defer func() {
		if err != nil {
			cancelTunnel()
			_ = uploadWriter.CloseWithError(err)
			_ = uploadReader.Close()
		}
	}()

	request, err := buildConnectRequest(tunnelCtx, config, destination, uploadReader)
	if err != nil {
		return nil, err
	}
	response, err := clientConnection.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		_ = response.Body.Close()
		return nil, connectStatusError(response.StatusCode)
	}
	// naiveproxy negotiates padding per stream: the server echoes the header to
	// accept it and stays silent to decline. Follow whichever it chose.
	padding := newPaddingState(response.Header.Get(paddingHeader) != "")
	if !stopOnContextDone() {
		_ = response.Body.Close()
		return nil, ctx.Err()
	}
	return &tunnelConn{
		Conn:     tlsConnection,
		upload:   uploadWriter,
		download: response.Body,
		client:   clientConnection,
		cancel:   cancelTunnel,
		padding:  padding,
	}, nil
}

// buildConnectRequest assembles the CONNECT request. net/http keeps the
// destination out of :path and :scheme for a plain CONNECT and sends it as
// :authority, which is where naive servers read the target from.
func buildConnectRequest(ctx context.Context, config ClientConfig, destination string, body io.Reader) (*http.Request, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodConnect, "https://"+destination, body)
	if err != nil {
		return nil, err
	}
	request.Host = destination
	request.Header.Set(paddingHeader, generateHeaderPadding())
	request.Header.Set("Proxy-Authorization", basicAuthorization(config.Username, config.Password))
	// Left empty so net/http omits it rather than announcing a Go HTTP client,
	// which no naive deployment sends.
	request.Header.Set("User-Agent", "")
	for name, value := range config.ExtraHeaders {
		request.Header.Set(name, value)
	}
	return request, nil
}

// handshakeTLS brings up TLS with the configured uTLS fingerprint and insists
// on h2, the only ALPN this transport can carry a tunnel over.
func handshakeTLS(ctx context.Context, raw net.Conn, config ClientConfig) (net.Conn, error) {
	tlsConfig := *config.TLSConfig
	tlsConfig.DisableRenegotiation = true
	if len(tlsConfig.NextProtos) == 0 {
		tlsConfig.NextProtos = []string{http2.NextProtoTLS, alpnHTTP11}
	}
	connection, err := vmess.StreamTLSConn(ctx, raw, &tlsConfig)
	if err != nil {
		return nil, err
	}
	if negotiated := tlsC.GetTLSConnectionState(connection).NegotiatedProtocol; negotiated != http2.NextProtoTLS {
		_ = connection.Close()
		return nil, fmt.Errorf("naive requires the %q ALPN, the server negotiated %q", http2.NextProtoTLS, negotiated)
	}
	return connection, nil
}

func basicAuthorization(username, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
}

func connectStatusError(statusCode int) error {
	switch statusCode {
	case http.StatusProxyAuthRequired:
		return errors.New("naive credentials rejected by the server")
	case http.StatusBadRequest:
		return errors.New("naive server rejected the CONNECT request")
	}
	return fmt.Errorf("naive server answered CONNECT with HTTP %d", statusCode)
}
