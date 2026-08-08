package tlsfragment

import (
	"net"
	"time"
)

// Conn fragments the ClientHello that a TLS client writes first and then gets
// out of the way. Connections carrying anything else are left untouched, so
// wrapping every dialled connection costs one check on the first write.
type Conn struct {
	net.Conn

	// delay separates the records so they land in different TCP segments,
	// which also defeats middleboxes that reassemble records but not streams.
	// Zero keeps the split at the record layer only, at no latency cost.
	delay time.Duration

	// firstWriteDone guards the one write we may rewrite. Callers already
	// serialise writes on a connection, matching net.Conn's own contract.
	firstWriteDone bool
}

func NewConn(conn net.Conn, delay time.Duration) *Conn {
	return &Conn{Conn: conn, delay: delay}
}

func (c *Conn) Write(b []byte) (int, error) {
	if c.firstWriteDone {
		return c.Conn.Write(b)
	}
	c.firstWriteDone = true

	records, ok := Fragment(b)
	if !ok {
		return c.Conn.Write(b)
	}

	for i, record := range records {
		if i > 0 && c.delay > 0 {
			time.Sleep(c.delay)
		}
		if _, err := c.Conn.Write(record); err != nil {
			return 0, err
		}
	}
	// Report what the caller handed us: the extra record headers on the wire
	// are ours, not theirs.
	return len(b), nil
}

// Upstream exposes the wrapped connection so the rest of the core can unwrap to
// the real socket, keeping assertions such as *net.TCPConn and syscall.Conn
// working through this layer.
func (c *Conn) Upstream() any {
	return c.Conn
}
