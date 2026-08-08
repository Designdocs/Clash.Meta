package artx

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLifecyclePacketConnEmitsExactOpenAndTerminalEvents(t *testing.T) {
	if !validLifecycleTraceDescriptor(0) || !validLifecycleTraceDescriptor(3) ||
		validLifecycleTraceDescriptor(-1) || validLifecycleTraceDescriptor(1) ||
		validLifecycleTraceDescriptor(2) {
		t.Fatal("unexpected lifecycle trace descriptor policy")
	}

	path := filepath.Join(t.TempDir(), "client.ndjson")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	sink := &lifecycleTraceSink{started: time.Now(), file: file}
	underlying := &lifecyclePacketConnStub{}
	connection := &lifecyclePacketConn{
		PacketConn: underlying,
		sink:       sink,
		sourcePort: 32001,
	}
	payload := make([]byte, lifecyclePacketHeaderSize)
	copy(payload, lifecyclePacketMagic)
	payload[4] = lifecyclePacketVersion
	payload[5] = 4
	binary.BigEndian.PutUint64(payload[8:16], 120001)
	payloadHash := sha256.Sum256(nil)
	copy(payload[36:52], payloadHash[:16])
	remote := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 443}
	if _, err = connection.WriteTo(payload, remote); err != nil {
		t.Fatal(err)
	}
	if err = connection.Close(); err != nil {
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}

	read, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	var events []lifecycleTraceEvent
	scanner := bufio.NewScanner(read)
	for scanner.Scan() {
		var event lifecycleTraceEvent
		if err = json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatal(err)
		}
		events = append(events, event)
	}
	if err = scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].Event != "opened" ||
		events[1].Event != "terminal" || events[0].AssociationID != 120001 ||
		events[1].AssociationID != 120001 || events[0].SourcePort != 32001 ||
		events[1].TerminalReason != "close_complete" ||
		events[1].MonotonicNS < events[0].MonotonicNS {
		t.Fatalf("unexpected lifecycle events: %+v", events)
	}
}

type lifecyclePacketConnStub struct{}

func (*lifecyclePacketConnStub) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, net.ErrClosed
}

func (*lifecyclePacketConnStub) WriteTo(payload []byte, _ net.Addr) (int, error) {
	return len(payload), nil
}

func (*lifecyclePacketConnStub) Close() error                     { return nil }
func (*lifecyclePacketConnStub) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (*lifecyclePacketConnStub) SetDeadline(time.Time) error      { return nil }
func (*lifecyclePacketConnStub) SetReadDeadline(time.Time) error  { return nil }
func (*lifecyclePacketConnStub) SetWriteDeadline(time.Time) error { return nil }
