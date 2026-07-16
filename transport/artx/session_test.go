package artx

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

func TestClientSessionReusesOneOuterConnectionSequentially(t *testing.T) {
	client, server := net.Pipe()
	session := &ClientSession{connection: client, nextID: 1, limit: 8}
	go session.readLoop()
	defer session.close()

	serverDone := make(chan error, 1)
	go func() {
		defer server.Close()
		for _, expectedID := range []uint32{1, 3} {
			var open Frame
			for {
				var err error
				open, err = readFrame(server, 2)
				if err != nil {
					serverDone <- err
					return
				}
				previousID := expectedID - 2
				if open.Type == FrameWindowUpdate && (open.StreamID == 0 || expectedID > 1 && open.StreamID == previousID) {
					continue
				}
				break
			}
			if open.Type != FrameTCPSyn || open.StreamID != expectedID {
				serverDone <- fmt.Errorf("unexpected reusable stream open: type=%d stream=%d", open.Type, open.StreamID)
				return
			}
			data, err := readUntilFrame(server, FrameData)
			if err != nil {
				serverDone <- err
				return
			}
			if err := writeFrame(server, 2, FrameData, expectedID, bytes.ToUpper(data.Payload)); err != nil {
				serverDone <- err
				return
			}
			if _, err := readUntilFrame(server, FrameFin); err != nil {
				serverDone <- err
				return
			}
			if err := writeFrame(server, 2, FrameFin, expectedID, nil); err != nil {
				serverDone <- err
				return
			}
		}
		serverDone <- nil
	}()

	destination := Destination{Host: "example.com", Port: 443}
	for index, request := range [][]byte{[]byte("first"), []byte("second")} {
		connection, err := session.OpenTCP(destination)
		if err != nil {
			t.Fatal(err)
		}
		if index == 0 {
			if _, err := session.OpenTCP(destination); !errors.Is(err, ErrSessionBusy) {
				t.Fatalf("busy session error = %v", err)
			}
		}
		if _, err := connection.Write(request); err != nil {
			t.Fatal(err)
		}
		response := make([]byte, len(request))
		if _, err := io.ReadFull(connection, response); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(response, bytes.ToUpper(request)) {
			t.Fatalf("response = %q", response)
		}
		if err := connection.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
			t.Fatal(err)
		}
		if _, err := connection.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
			t.Fatalf("terminal read error = %v", err)
		}
		if err := connection.Close(); err != nil {
			t.Fatal(err)
		}
		if index == 0 {
			select {
			case err := <-serverDone:
				t.Fatalf("server exited after first stream: %v", err)
			default:
			}
		}
		waitSessionIdle(t, session)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	_ = server.Close()
}

func TestClientSessionClosesAfterPrematureStreamClose(t *testing.T) {
	client, server := net.Pipe()
	session := &ClientSession{connection: client, nextID: 1, limit: 8}
	go session.readLoop()
	defer server.Close()
	openRead := make(chan error, 1)
	go func() {
		_, err := readFrame(server, 2)
		openRead <- err
	}()

	connection, err := session.OpenTCP(Destination{Host: "example.com", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	if err := <-openRead; err != nil {
		t.Fatal(err)
	}
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	waitSessionClosed(t, session)
	if _, err := session.OpenTCP(Destination{Host: "example.com", Port: 443}); !errors.Is(err, ErrSessionClosed) {
		t.Fatalf("open after premature close error = %v", err)
	}
}

func readUntilFrame(connection net.Conn, frameType byte) (Frame, error) {
	for {
		frame, err := readFrame(connection, 2)
		if err != nil || frame.Type == frameType {
			return frame, err
		}
	}
}

func waitSessionIdle(t *testing.T, session *ClientSession) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		session.mu.Lock()
		idle := session.active == nil
		session.mu.Unlock()
		if idle {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("reusable session did not become idle")
}

func waitSessionClosed(t *testing.T, session *ClientSession) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if session.IsClosed() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("reusable session did not close")
}
