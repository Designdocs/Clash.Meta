package naive

import (
	"context"
	"io"
	"net"
	"sync"

	"golang.org/x/net/http2"
)

// tunnelConn presents one CONNECT stream as a net.Conn. The embedded TLS
// connection supplies the addresses and deadlines — this transport opens a
// connection per tunnel, so a deadline on the socket means the same thing as a
// deadline on the stream. Payload travels through the HTTP/2 request and
// response bodies with padding applied.
type tunnelConn struct {
	net.Conn
	upload   *io.PipeWriter
	download io.ReadCloser
	client   *http2.ClientConn
	cancel   context.CancelFunc
	padding  paddingState
	closeMu  sync.Mutex
	closed   bool
}

func (connection *tunnelConn) Read(payload []byte) (int, error) {
	return connection.padding.readWithPadding(connection.download, payload)
}

func (connection *tunnelConn) Write(payload []byte) (int, error) {
	return connection.padding.writeWithPadding(connection.upload, payload)
}

// CloseWrite ends the request body, which the peer sees as a half-closed
// stream. The response body stays readable.
func (connection *tunnelConn) CloseWrite() error {
	return connection.upload.Close()
}

func (connection *tunnelConn) Close() error {
	connection.closeMu.Lock()
	defer connection.closeMu.Unlock()
	if connection.closed {
		return nil
	}
	connection.closed = true
	connection.cancel()
	_ = connection.upload.Close()
	_ = connection.download.Close()
	_ = connection.client.Close()
	return connection.Conn.Close()
}
