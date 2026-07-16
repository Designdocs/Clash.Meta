package artx

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestPacketConnPreservesDatagramBoundaries(t *testing.T) {
	client, server := net.Pipe()
	remote := &net.UDPAddr{IP: net.ParseIP("192.0.2.53"), Port: 53}
	connection := NewPacketConn(client, remote)
	requests := [][]byte{[]byte("dns-query"), bytes.Repeat([]byte{0xa5}, 1232)}
	responses := [][]byte{[]byte("dns-response"), bytes.Repeat([]byte{0x5a}, 1200)}
	serverDone := make(chan error, 1)
	go func() {
		defer server.Close()
		index := 0
		for {
			frame, err := ReadFrame(server)
			if err != nil {
				serverDone <- err
				return
			}
			switch frame.Type {
			case FrameDatagram:
				payload, err := ParseDatagram(frame.Payload)
				if err != nil || index >= len(requests) || !bytes.Equal(payload, requests[index]) {
					serverDone <- errors.New("unexpected client DATAGRAM")
					return
				}
				update := make([]byte, 4)
				binary.BigEndian.PutUint32(update, uint32(len(frame.Payload)))
				if err := WriteFrame(server, FrameWindowUpdate, 0, update); err != nil {
					serverDone <- err
					return
				}
				if err := WriteFrame(server, FrameWindowUpdate, 1, update); err != nil {
					serverDone <- err
					return
				}
				response, _ := MarshalDatagram(responses[index])
				if err := WriteFrame(server, FrameDatagram, 1, response); err != nil {
					serverDone <- err
					return
				}
				index++
			case FrameWindowUpdate:
			case FrameFin:
				if index != len(requests) {
					serverDone <- errors.New("client FIN before all DATAGRAMs")
					return
				}
				serverDone <- nil
				return
			default:
				serverDone <- errors.New("unexpected client frame")
				return
			}
		}
	}()

	for index, request := range requests {
		if written, err := connection.WriteTo(request, remote); err != nil || written != len(request) {
			t.Fatalf("WriteTo(%d) = %d, %v", index, written, err)
		}
		buffer := make([]byte, 2048)
		read, from, err := connection.ReadFrom(buffer)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(buffer[:read], responses[index]) || from.String() != remote.String() {
			t.Fatalf("ReadFrom(%d) = %d bytes from %v", index, read, from)
		}
	}
	if _, err := connection.WriteTo([]byte("wrong target"), &net.UDPAddr{IP: net.ParseIP("192.0.2.54"), Port: 53}); err == nil {
		t.Fatal("different UDP target was accepted")
	}
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not receive UDP FIN")
	}
}

func TestPacketConnRejectsMalformedDatagram(t *testing.T) {
	client, server := net.Pipe()
	connection := NewPacketConn(client, &net.UDPAddr{IP: net.ParseIP("192.0.2.53"), Port: 53})
	writeDone := make(chan error, 1)
	go func() {
		writeDone <- WriteFrame(server, FrameDatagram, 1, []byte{0, 2, 1})
		_ = server.Close()
	}()
	if _, _, err := connection.ReadFrom(make([]byte, 32)); err == nil || errors.Is(err, io.EOF) {
		t.Fatalf("malformed DATAGRAM error = %v", err)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	_ = connection.Close()
}

func TestPacketConnCloseIsBoundedWithoutPeerFIN(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	connection := NewPacketConn(client, &net.UDPAddr{IP: net.ParseIP("192.0.2.53"), Port: 53})
	finRead := make(chan error, 1)
	go func() {
		frame, err := ReadFrame(server)
		if err == nil && frame.Type != FrameFin {
			err = errors.New("client did not send FIN")
		}
		finRead <- err
	}()

	started := time.Now()
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed > 1500*time.Millisecond {
		t.Fatalf("Close took %s", elapsed)
	}
	if err := <-finRead; err != nil {
		t.Fatal(err)
	}
}
