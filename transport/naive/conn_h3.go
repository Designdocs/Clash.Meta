package naive

import (
	"errors"
	"net"
	"sync"
	"time"

	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
)

// h3TunnelConn presents one HTTP/3 CONNECT stream as a net.Conn. Payload
// travels on the QUIC stream itself rather than through request and response
// bodies, so unlike the HTTP/2 tunnel there is no pipe in the middle — but the
// padding state machine is the same one, applied to the same first frames.
type h3TunnelConn struct {
	stream         *http3.RequestStream
	connection     *quic.Conn
	transport      *http3.Transport
	closeTransport func() error
	padding        paddingState
	closeMu        sync.Mutex
	closed         bool
}

func (connection *h3TunnelConn) Read(payload []byte) (int, error) {
	return connection.padding.readWithPadding(connection.stream, payload)
}

func (connection *h3TunnelConn) Write(payload []byte) (int, error) {
	return connection.padding.writeWithPadding(connection.stream, payload)
}

// CloseWrite ends the send direction, which the peer sees as a half-closed
// stream. The receive direction stays readable.
func (connection *h3TunnelConn) CloseWrite() error {
	return connection.stream.Close()
}

func (connection *h3TunnelConn) Close() error {
	connection.closeMu.Lock()
	defer connection.closeMu.Unlock()
	if connection.closed {
		return nil
	}
	connection.closed = true
	connection.stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
	connection.stream.CancelWrite(quic.StreamErrorCode(http3.ErrCodeNoError))
	return errors.Join(connection.transport.Close(), connection.closeTransport())
}

func (connection *h3TunnelConn) LocalAddr() net.Addr {
	return connection.connection.LocalAddr()
}

func (connection *h3TunnelConn) RemoteAddr() net.Addr {
	return connection.connection.RemoteAddr()
}

func (connection *h3TunnelConn) SetDeadline(deadline time.Time) error {
	return connection.stream.SetDeadline(deadline)
}

func (connection *h3TunnelConn) SetReadDeadline(deadline time.Time) error {
	return connection.stream.SetReadDeadline(deadline)
}

func (connection *h3TunnelConn) SetWriteDeadline(deadline time.Time) error {
	return connection.stream.SetWriteDeadline(deadline)
}

var _ net.Conn = (*h3TunnelConn)(nil)
