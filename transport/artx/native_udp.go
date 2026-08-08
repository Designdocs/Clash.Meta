package artx

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
	"github.com/metacubex/quic-go/quicvarint"
	"github.com/metacubex/tls"
)

const (
	nativeUDPPathPrefix      = "/.well-known/masque/udp/"
	nativeUDPMaxPayload      = 65527
	nativeUDPCapsuleProtocol = "?1"
)

func PrepareNativeUDPTLS(ctx context.Context, config ClientConfig) (*tls.Config, error) {
	if config.TLSConfig == nil {
		return nil, errors.New("artx: native UDP TLS config is required")
	}
	tlsConfig, err := config.TLSConfig.ToStdConfig()
	if err != nil {
		return nil, err
	}
	tlsConfig.MinVersion = tls.VersionTLS13
	tlsConfig.MaxVersion = tls.VersionTLS13
	tlsConfig.NextProtos = []string{http3.NextProtoH3}
	tlsConfig.ClientSessionCache = nil
	if err := config.TLSConfig.ECH.ClientHandle(ctx, tlsConfig); err != nil {
		return nil, err
	}
	return tlsConfig, nil
}

func DialNativeUDP(
	ctx context.Context,
	connection *quic.Conn,
	config ClientConfig,
	destination Destination,
	remote net.Addr,
	closeTransport func() error,
) (net.PacketConn, error) {
	if connection == nil || remote == nil || closeTransport == nil {
		return nil, errors.New("artx: native UDP connection, target, and cleanup are required")
	}
	if err := destination.Validate(); err != nil {
		return nil, err
	}
	state := connection.ConnectionState()
	if state.TLS.Version != tls.VersionTLS13 || state.TLS.NegotiatedProtocol != http3.NextProtoH3 || state.TLS.DidResume {
		return nil, errors.New("artx: native UDP requires fresh TLS 1.3 with h3 ALPN")
	}
	if !state.SupportsDatagrams.Local || !state.SupportsDatagrams.Remote {
		return nil, errors.New("artx: native UDP requires QUIC datagrams")
	}
	exporter, err := state.TLS.ExportKeyingMaterial(nativeUDPExporterLabel, nil, nativeUDPExporterLength)
	if err != nil {
		return nil, fmt.Errorf("artx: native UDP TLS exporter: %w", err)
	}
	requestContract, requestURL, err := buildNativeUDPRequest(config.Authority, destination)
	if err != nil {
		return nil, err
	}
	salt := make([]byte, nativeUDPSaltLength)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	authorization, err := newNativeUDPAuthorization(
		[]byte(config.Password),
		salt,
		exporter,
		requestContract,
		uint32(time.Now().Unix()/bucketSeconds),
	)
	if err != nil {
		return nil, err
	}

	transport := &http3.Transport{EnableDatagrams: true}
	clientConnection := transport.NewClientConn(connection)
	select {
	case <-ctx.Done():
		_ = transport.Close()
		return nil, context.Cause(ctx)
	case <-clientConnection.Context().Done():
		_ = transport.Close()
		return nil, context.Cause(clientConnection.Context())
	case <-clientConnection.ReceivedSettings():
	}
	settings := clientConnection.Settings()
	if !settings.EnableExtendedConnect || !settings.EnableDatagrams {
		_ = transport.Close()
		return nil, errors.New("artx: native UDP peer lacks CONNECT-UDP settings")
	}
	stream, err := clientConnection.OpenRequestStream(ctx)
	if err != nil {
		_ = transport.Close()
		return nil, err
	}
	request := &http.Request{
		Method: http.MethodConnect,
		Proto:  requestContract.protocol,
		Host:   requestContract.authority,
		Header: http.Header{
			http3.CapsuleProtocolHeader: []string{nativeUDPCapsuleProtocol},
			nativeUDPAuthHeader:         []string{authorization.header()},
		},
		URL: requestURL,
	}
	if err := stream.SendRequestHeader(request); err != nil {
		stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
		stream.CancelWrite(quic.StreamErrorCode(http3.ErrCodeNoError))
		_ = transport.Close()
		return nil, err
	}
	response, err := stream.ReadResponse()
	if err != nil {
		stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
		stream.CancelWrite(quic.StreamErrorCode(http3.ErrCodeNoError))
		_ = transport.Close()
		return nil, err
	}
	if response.StatusCode < 200 || response.StatusCode > 299 || !authorization.verifyServerProof(
		response.Header.Get(nativeUDPProofHeader),
		[]byte(config.Password),
		exporter,
		response.StatusCode,
		nativeUDPCapsuleProtocol,
	) {
		stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
		stream.CancelWrite(quic.StreamErrorCode(http3.ErrCodeNoError))
		_ = transport.Close()
		return nil, errors.New("artx: native UDP association rejected")
	}
	return newNativeUDPPacketConn(stream, transport, connection.LocalAddr(), remote, closeTransport), nil
}

func buildNativeUDPRequest(authority string, destination Destination) (nativeUDPRequest, *url.URL, error) {
	if strings.TrimSpace(authority) == "" {
		return nativeUDPRequest{}, nil, errors.New("artx: native UDP authority is required")
	}
	host := destination.Host
	if host == "" {
		host = destination.IP.String()
	}
	path := nativeUDPPathPrefix + strings.ReplaceAll(url.PathEscape(host), ":", "%3A") + "/" + strconv.Itoa(int(destination.Port)) + "/"
	requestURL, err := url.Parse("https://" + authority + path)
	if err != nil {
		return nativeUDPRequest{}, nil, err
	}
	request := nativeUDPRequest{
		method:          http.MethodConnect,
		protocol:        "connect-udp",
		scheme:          "https",
		authority:       authority,
		path:            path,
		capsuleProtocol: nativeUDPCapsuleProtocol,
	}
	return request, requestURL, request.validate()
}

type nativeUDPPacketConn struct {
	stream       *http3.RequestStream
	transport    *http3.Transport
	local        net.Addr
	remote       net.Addr
	closeParent  func() error
	ctx          context.Context
	cancel       context.CancelFunc
	closed       atomic.Bool
	closeOnce    sync.Once
	deadlineMu   sync.RWMutex
	readDeadline time.Time
}

func newNativeUDPPacketConn(
	stream *http3.RequestStream,
	transport *http3.Transport,
	local, remote net.Addr,
	closeParent func() error,
) *nativeUDPPacketConn {
	ctx, cancel := context.WithCancel(context.Background())
	return &nativeUDPPacketConn{
		stream:      stream,
		transport:   transport,
		local:       local,
		remote:      remote,
		closeParent: closeParent,
		ctx:         ctx,
		cancel:      cancel,
	}
}

func (connection *nativeUDPPacketConn) ReadFrom(payload []byte) (int, net.Addr, error) {
	for {
		receiveContext, cancel := connection.receiveContext()
		datagram, err := connection.stream.ReceiveDatagram(receiveContext)
		cancel()
		if err != nil {
			if connection.closed.Load() {
				return 0, nil, net.ErrClosed
			}
			return 0, nil, err
		}
		contextID, offset, err := quicvarint.Parse(datagram)
		if err != nil {
			return 0, nil, fmt.Errorf("artx: malformed native UDP datagram: %w", err)
		}
		if contextID != 0 {
			continue
		}
		return copy(payload, datagram[offset:]), connection.remote, nil
	}
}

func (connection *nativeUDPPacketConn) WriteTo(payload []byte, remote net.Addr) (int, error) {
	if connection.closed.Load() {
		return 0, net.ErrClosed
	}
	if len(payload) == 0 {
		return 0, errors.New("artx: native UDP does not support empty payloads")
	}
	if !samePacketDestination(connection.remote, remote) {
		return 0, errors.New("artx: native UDP destination does not match the association")
	}
	if len(payload) > nativeUDPMaxPayload {
		return 0, errors.New("artx: native UDP payload is too large")
	}
	datagram := make([]byte, len(payload)+1)
	copy(datagram[1:], payload)
	if err := connection.stream.SendDatagram(datagram); err != nil {
		return 0, err
	}
	return len(payload), nil
}

func (connection *nativeUDPPacketConn) Close() error {
	connection.closeOnce.Do(func() {
		connection.closed.Store(true)
		connection.cancel()
		connection.stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
		connection.stream.CancelWrite(quic.StreamErrorCode(http3.ErrCodeNoError))
		_ = connection.stream.Close()
		_ = connection.transport.Close()
		_ = connection.closeParent()
	})
	return nil
}

func (connection *nativeUDPPacketConn) LocalAddr() net.Addr  { return connection.local }
func (connection *nativeUDPPacketConn) RemoteAddr() net.Addr { return connection.remote }
func (connection *nativeUDPPacketConn) SetDeadline(deadline time.Time) error {
	connection.setReadDeadline(deadline)
	return connection.stream.SetWriteDeadline(deadline)
}
func (connection *nativeUDPPacketConn) SetReadDeadline(deadline time.Time) error {
	connection.setReadDeadline(deadline)
	return nil
}
func (connection *nativeUDPPacketConn) SetWriteDeadline(deadline time.Time) error {
	return connection.stream.SetWriteDeadline(deadline)
}

func (connection *nativeUDPPacketConn) setReadDeadline(deadline time.Time) {
	connection.deadlineMu.Lock()
	connection.readDeadline = deadline
	connection.deadlineMu.Unlock()
}

func (connection *nativeUDPPacketConn) receiveContext() (context.Context, context.CancelFunc) {
	connection.deadlineMu.RLock()
	deadline := connection.readDeadline
	connection.deadlineMu.RUnlock()
	if deadline.IsZero() {
		return context.WithCancel(connection.ctx)
	}
	return context.WithDeadline(connection.ctx, deadline)
}

var _ net.PacketConn = (*nativeUDPPacketConn)(nil)
