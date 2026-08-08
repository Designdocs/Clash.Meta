package dialer

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"
)

// TestDialContextFragmentsClientHello drives the real dial path end to end: the
// setting goes on, a genuine crypto/tls ClientHello goes out over a real
// socket, and the far end has to receive it split with the host name broken
// across the pieces.
func TestDialContextFragmentsClientHello(t *testing.T) {
	const serverName = "campus.example.com"

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not listen: %v", err)
	}
	defer listener.Close()

	reads := make(chan [][]byte, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			reads <- nil
			return
		}
		defer conn.Close()

		var captured [][]byte
		buf := make([]byte, 8192)
		for len(captured) < 2 {
			_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			n, err := conn.Read(buf)
			if n > 0 {
				captured = append(captured, append([]byte(nil), buf[:n]...))
			}
			if err != nil {
				break
			}
		}
		reads <- captured
	}()

	// A delay pushes the records into separate segments, which is what makes
	// the split observable as separate reads on the far end.
	SetTLSFragment(true, 20)
	defer SetTLSFragment(false, 0)

	conn, err := DialContext(context.Background(), "tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("could not dial: %v", err)
	}
	defer conn.Close()

	go func() {
		client := tls.Client(conn, &tls.Config{ServerName: serverName})
		// The handshake cannot complete against a listener that never replies;
		// putting the hello on the wire is the whole point.
		_ = client.Handshake()
	}()

	captured := <-reads
	if len(captured) < 2 {
		t.Fatalf("the hello arrived in %d piece(s), so it was not fragmented", len(captured))
	}

	for i, piece := range captured {
		if bytes.Contains(piece, []byte(serverName)) {
			t.Errorf("piece %d still carries the whole host name", i)
		}
	}

	// Putting the name back together means parsing the records and dropping
	// each header: on the wire the two halves are separated by the second
	// record's own header, which is precisely what a middlebox matching raw
	// bytes cannot reassemble.
	stream := bytes.Join(captured, nil)
	var records int
	var handshake []byte
	for len(stream) >= 5 {
		length := int(stream[3])<<8 | int(stream[4])
		if len(stream) < 5+length {
			break
		}
		handshake = append(handshake, stream[5:5+length]...)
		stream = stream[5+length:]
		records++
	}

	if records < 2 {
		t.Errorf("the hello went out as %d TLS record(s), want at least 2", records)
	}
	if !bytes.Contains(handshake, []byte(serverName)) {
		t.Error("the host name did not survive reassembly, so the split corrupted it")
	}
}

func TestDialContextLeavesConnectionsAloneWhenOff(t *testing.T) {
	SetTLSFragment(false, 0)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not listen: %v", err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err == nil {
			conn.Close()
		}
	}()

	conn, err := DialContext(context.Background(), "tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("could not dial: %v", err)
	}
	defer conn.Close()

	if _, wrapped := conn.(interface{ Upstream() any }); wrapped {
		t.Error("the dialer wrapped a connection while fragmentation was off")
	}
}

func TestSetTLSFragmentClampsTheDelay(t *testing.T) {
	defer SetTLSFragment(false, 0)

	for _, tc := range []struct {
		given int
		want  int
	}{
		{-1000, 0},
		{-1, 0},
		{0, 0},
		{25, 25},
		{maxTLSFragmentDelay, maxTLSFragmentDelay},
		{maxTLSFragmentDelay + 1, maxTLSFragmentDelay},
		{99999, maxTLSFragmentDelay},
	} {
		SetTLSFragment(true, tc.given)
		if _, got := GetTLSFragment(); got != tc.want {
			t.Errorf("a delay of %d settled at %d, want %d", tc.given, got, tc.want)
		}
	}
}
