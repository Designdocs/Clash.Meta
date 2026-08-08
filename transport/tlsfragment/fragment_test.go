package tlsfragment

import (
	"bytes"
	"crypto/tls"
	"net"
	"testing"
	"time"
)

// realClientHello captures the ClientHello that crypto/tls puts on the wire, so
// the parser is exercised against a genuine one rather than a hand-rolled
// approximation.
func realClientHello(t *testing.T, serverName string) []byte {
	t.Helper()

	client, server := net.Pipe()
	t.Cleanup(func() {
		client.Close()
		server.Close()
	})

	captured := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 8192)
		n, err := server.Read(buf)
		if err != nil {
			close(captured)
			return
		}
		captured <- append([]byte(nil), buf[:n]...)
		server.Close()
	}()

	go func() {
		conn := tls.Client(client, &tls.Config{ServerName: serverName})
		// The handshake cannot finish against a closed pipe; the hello is all
		// this test needs.
		_ = conn.Handshake()
		conn.Close()
	}()

	select {
	case hello, ok := <-captured:
		if !ok || len(hello) == 0 {
			t.Fatal("captured no ClientHello")
		}
		return hello
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for the ClientHello")
		return nil
	}
}

func TestFragmentSplitsHostNameAcrossRecords(t *testing.T) {
	const serverName = "campus.example.com"
	hello := realClientHello(t, serverName)

	if !bytes.Contains(hello, []byte(serverName)) {
		t.Fatalf("test setup is wrong: the captured hello has no %q in it", serverName)
	}

	records, ok := Fragment(hello)
	if !ok {
		t.Fatal("Fragment refused a genuine ClientHello")
	}
	if len(records) != 2 {
		t.Fatalf("got %d records, want 2", len(records))
	}

	for i, record := range records {
		if len(record) <= recordHeaderLen {
			t.Fatalf("record %d is empty", i)
		}
		if record[0] != recordTypeHandshake {
			t.Errorf("record %d has type %#x, want %#x", i, record[0], recordTypeHandshake)
		}
		if record[1] != hello[1] || record[2] != hello[2] {
			t.Errorf("record %d changed the version bytes", i)
		}
		if declared := int(record[3])<<8 | int(record[4]); declared != len(record)-recordHeaderLen {
			t.Errorf("record %d declares length %d but carries %d",
				i, declared, len(record)-recordHeaderLen)
		}
		if bytes.Contains(record, []byte(serverName)) {
			t.Errorf("record %d still carries the whole host name, so the split did nothing", i)
		}
	}

	rejoined := append(append([]byte{}, records[0][recordHeaderLen:]...), records[1][recordHeaderLen:]...)
	if !bytes.Equal(rejoined, hello[recordHeaderLen:]) {
		t.Error("rejoining the records does not reproduce the original handshake message")
	}
}

func TestClientHelloSplitPointLandsInsideHostName(t *testing.T) {
	const serverName = "campus.example.com"
	hello := realClientHello(t, serverName)
	payload := hello[recordHeaderLen:]

	offset, length, ok := serverNameOffset(payload)
	if !ok {
		t.Fatal("serverNameOffset could not find the host name")
	}
	if got := string(payload[offset : offset+length]); got != serverName {
		t.Fatalf("located %q, want %q", got, serverName)
	}

	cut, ok := ClientHelloSplitPoint(payload)
	if !ok {
		t.Fatal("ClientHelloSplitPoint reported no split point")
	}
	if cut <= offset || cut >= offset+length {
		t.Errorf("split point %d is outside the host name spanning [%d,%d)",
			cut, offset, offset+length)
	}
}

func TestFragmentLeavesEverythingElseAlone(t *testing.T) {
	hello := realClientHello(t, "campus.example.com")

	twoRecords := append(append([]byte{}, hello...), hello...)

	cases := []struct {
		name string
		buf  []byte
	}{
		{"empty", nil},
		{"header only", hello[:recordHeaderLen]},
		{"application data", []byte{0x17, 0x03, 0x03, 0x00, 0x02, 0xAA, 0xBB}},
		{"not tls 1.x", []byte{0x16, 0x02, 0x00, 0x00, 0x02, 0x01, 0x00}},
		{"server hello", []byte{0x16, 0x03, 0x01, 0x00, 0x02, 0x02, 0x00}},
		{"truncated record", hello[:len(hello)-1]},
		{"two records batched", twoRecords},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := Fragment(tc.buf); ok {
				t.Error("Fragment rewrote a buffer it should have passed through")
			}
		})
	}
}

func TestFragmentSurvivesTruncationAtEveryOffset(t *testing.T) {
	hello := realClientHello(t, "campus.example.com")

	// Length prefixes come off the wire, so a short read must never panic.
	for i := 0; i <= len(hello); i++ {
		Fragment(hello[:i])
		if i >= recordHeaderLen {
			ClientHelloSplitPoint(hello[recordHeaderLen:i])
		}
	}
}

func TestFragmentSplitsHelloWithoutParsableName(t *testing.T) {
	// A ClientHello whose extensions we cannot walk still gets split, because
	// a parser miss is not proof that there is no name worth hiding.
	payload := append([]byte{handshakeTypeClientHello, 0x00, 0x00, 0x04}, 0x03, 0x03, 0x00, 0x00)
	record := buildRecord(0x03, 0x01, payload)

	records, ok := Fragment(record)
	if !ok {
		t.Fatal("Fragment gave up on a ClientHello it could not parse")
	}
	if len(records) != 2 {
		t.Fatalf("got %d records, want 2", len(records))
	}

	rejoined := append(append([]byte{}, records[0][recordHeaderLen:]...), records[1][recordHeaderLen:]...)
	if !bytes.Equal(rejoined, payload) {
		t.Error("rejoining the records does not reproduce the payload")
	}
}

func FuzzFragment(f *testing.F) {
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x02, 0x01, 0x00})
	f.Add([]byte{0x17, 0x03, 0x03, 0x00, 0x00})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, buf []byte) {
		records, ok := Fragment(buf)
		if !ok {
			return
		}
		rejoined := []byte{}
		for _, record := range records {
			if len(record) < recordHeaderLen {
				t.Fatalf("emitted a record shorter than its header: %d bytes", len(record))
			}
			if declared := int(record[3])<<8 | int(record[4]); declared != len(record)-recordHeaderLen {
				t.Fatalf("record declares %d bytes but carries %d",
					declared, len(record)-recordHeaderLen)
			}
			rejoined = append(rejoined, record[recordHeaderLen:]...)
		}
		if !bytes.Equal(rejoined, buf[recordHeaderLen:]) {
			t.Fatal("fragmenting changed the handshake bytes")
		}
	})
}
