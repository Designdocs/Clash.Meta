package naive

import (
	"context"
	"errors"
	"net"
	"net/url"

	"github.com/metacubex/http"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
	"github.com/metacubex/tls"
)

// PrepareH3TLS turns the outbound's TLS settings into the standard config a
// QUIC dial needs: TLS 1.3 only, and the h3 ALPN unless the profile named its
// own.
//
// The Chrome ClientHello that uTLS gives the HTTP/2 path is not available here
// — QUIC carries its own TLS 1.3 handshake, so this connection is shaped like
// any other quic-go client. naive over HTTP/3 therefore trades some of the
// fingerprint cover for the transport.
func PrepareH3TLS(ctx context.Context, config ClientConfig) (*tls.Config, error) {
	if config.TLSConfig == nil {
		return nil, errors.New("naive requires a TLS configuration")
	}
	tlsConfig, err := config.TLSConfig.ToStdConfig()
	if err != nil {
		return nil, err
	}
	tlsConfig.MinVersion = tls.VersionTLS13
	tlsConfig.MaxVersion = tls.VersionTLS13
	if len(tlsConfig.NextProtos) == 0 {
		tlsConfig.NextProtos = []string{http3.NextProtoH3}
	}
	if err := config.TLSConfig.ECH.ClientHandle(ctx, tlsConfig); err != nil {
		return nil, err
	}
	return tlsConfig, nil
}

// DialH3Context performs the naive handshake over an established QUIC
// connection and returns the tunnel as a net.Conn. It is the HTTP/3 sibling of
// [DialContext]: same CONNECT request, same padding negotiation, only the
// carrier differs.
//
// quicConnection and whatever socket it was dialed on belong to closeTransport,
// which runs when the handshake fails and again when the tunnel is closed. One
// QUIC connection carries one tunnel here, matching what the TCP path does with
// its socket.
func DialH3Context(
	ctx context.Context,
	quicConnection *quic.Conn,
	config ClientConfig,
	destination string,
	closeTransport func() error,
) (_ net.Conn, err error) {
	if quicConnection == nil {
		return nil, errors.New("naive requires a QUIC connection")
	}
	if closeTransport == nil {
		return nil, errors.New("naive requires a transport cleanup function")
	}
	if destination == "" {
		return nil, errors.New("naive requires a destination authority")
	}
	// As on the TCP path, an abort by ctx surfaces as a transport error from
	// whichever call was in flight. Rewrite it so the caller sees the timeout
	// or cancellation that actually ended the dial.
	defer func() { err = describeHandshakeContextEnd(ctx, err) }()

	// DisableCompression keeps `accept-encoding: gzip` off a CONNECT, which is
	// a header Chrome never puts on one.
	transport := &http3.Transport{DisableCompression: true}
	clientConnection := transport.NewClientConn(quicConnection)
	// The SETTINGS frame is the first thing an HTTP/3 peer sends. Waiting for it
	// turns "this endpoint does not speak HTTP/3" into a failure here rather
	// than a stalled CONNECT further down.
	select {
	case <-clientConnection.ReceivedSettings():
	case <-clientConnection.Context().Done():
		_ = transport.Close()
		return nil, context.Cause(clientConnection.Context())
	case <-ctx.Done():
		_ = transport.Close()
		return nil, context.Cause(ctx)
	}

	stream, err := clientConnection.OpenRequestStream(ctx)
	if err != nil {
		_ = transport.Close()
		return nil, err
	}
	defer func() {
		if err != nil {
			stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
			stream.CancelWrite(quic.StreamErrorCode(http3.ErrCodeNoError))
			_ = transport.Close()
		}
	}()
	// ctx covers the handshake only, and SendRequestHeader and ReadResponse
	// carry no context of their own: without this abort a server that swallows
	// the CONNECT would hold the dial far past its deadline. Cancelling the
	// stream fails whichever of the two is in flight.
	stopOnContextDone := context.AfterFunc(ctx, func() {
		stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		stream.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
	})
	defer stopOnContextDone()

	if err = stream.SendRequestHeader(buildH3ConnectRequest(config, destination)); err != nil {
		return nil, err
	}
	response, err := stream.ReadResponse()
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		return nil, connectStatusError(response.StatusCode)
	}
	if !stopOnContextDone() {
		return nil, context.Cause(ctx)
	}
	return &h3TunnelConn{
		stream:         stream,
		connection:     quicConnection,
		transport:      transport,
		closeTransport: closeTransport,
		padding:        newPaddingState(response.Header.Get(paddingHeader) != ""),
	}, nil
}

// buildH3ConnectRequest assembles the same CONNECT the HTTP/2 path sends. It
// carries no body: on this carrier the payload is the QUIC stream itself,
// which only becomes writable once the request header is out. Leaving Proto
// empty keeps this a plain CONNECT rather than the extended one, so only
// :method and :authority go on the wire.
func buildH3ConnectRequest(config ClientConfig, destination string) *http.Request {
	request := &http.Request{
		Method: http.MethodConnect,
		Host:   destination,
		URL:    &url.URL{Host: destination},
		Header: http.Header{},
	}
	for name, value := range connectRequestHeaders(config) {
		request.Header.Set(name, value)
	}
	return request
}
