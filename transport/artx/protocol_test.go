package artx

import (
	"bytes"
	"encoding/hex"
	"net/netip"
	"testing"
)

type shortWriter struct{ bytes.Buffer }

func (writer *shortWriter) Write(payload []byte) (int, error) {
	if len(payload) > 3 {
		payload = payload[:3]
	}
	return writer.Buffer.Write(payload)
}

func TestArtXCanonicalVectors(t *testing.T) {
	psk := []byte("artx-wire-v1-test-psk")
	salt := mustDecodeHex(t, "000102030405060708090a0b0c0d0e0f")
	exporter := mustDecodeHex(t, "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")
	padding := mustDecodeHex(t, "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf")

	auth, err := BuildAuthFrame(psk, salt, exporter, 16909060, padding)
	if err != nil {
		t.Fatal(err)
	}
	assertHex(t, auth, "0110000102030405060708090a0b0c0d0e0f6cc5f96d2384bf260102030443935f299974be9ab1a248940eb7e877876ecd7e90fbb78218d03e1e003abcf30010a0a1a2a3a4a5a6a7a8a9aaabacadaeaf")

	settings, err := MarshalFrame(FrameSettings, 0, DefaultSettings(1).MarshalBinary())
	if err != nil {
		t.Fatal(err)
	}
	assertHex(t, settings, "0200000000000018000100000001000200040000000300100000000500000001")

	destination := Destination{Host: "example.com", Port: 443}
	tcpSyn, err := MarshalFrame(FrameTCPSyn, 1, destination.MarshalBinary())
	if err != nil {
		t.Fatal(err)
	}
	assertHex(t, tcpSyn, "100000000100000f030b6578616d706c652e636f6d01bb")

	data, err := MarshalFrame(FrameData, 1, []byte("GET / HTTP/1.1\r\n\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	assertHex(t, data, "1100000001000012474554202f20485454502f312e310d0a0d0a")

	fin, err := MarshalFrame(FrameFin, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	assertHex(t, fin, "1200000001000000")

	udpAssoc, err := MarshalFrame(FrameUDPAssoc, 1, (Destination{Host: "dns.example", Port: 53}).MarshalBinary())
	if err != nil {
		t.Fatal(err)
	}
	assertHex(t, udpAssoc, "150000000100000f030b646e732e6578616d706c650035")
	datagram, err := MarshalDatagram([]byte{0x12, 0x34})
	if err != nil {
		t.Fatal(err)
	}
	encodedDatagram, err := MarshalFrame(FrameDatagram, 1, datagram)
	if err != nil {
		t.Fatal(err)
	}
	assertHex(t, encodedDatagram, "160000000100000400021234")
}

func TestClientSettingsAdvertiseCompiledWindowScaleOnlyForWireV1TCP(t *testing.T) {
	tests := []struct {
		name                 string
		wire                 uint32
		advertiseFlowControl bool
		advertised           bool
		wantScale            uint32
	}{
		{name: "wire-v1 TCP", wire: 1, advertiseFlowControl: true, advertised: true, wantScale: maxFlowControlWindowScale},
		{name: "wire-v1 UDP", wire: 1},
		{name: "wire-v2", wire: 2, advertiseFlowControl: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload := marshalClientSettings(test.wire, 1, test.advertiseFlowControl)
			scale, advertised, err := findRawSetting(payload, settingWindowScaleCapability)
			if err != nil {
				t.Fatal(err)
			}
			if advertised != test.advertised || scale != test.wantScale {
				t.Fatalf("window scale = %d, %v; want %d, %v", scale, advertised, test.wantScale, test.advertised)
			}
		})
	}
}

func TestArtXProtocolValidation(t *testing.T) {
	want, _ := MarshalFrame(FrameData, 1, []byte("short-write"))
	writer := &shortWriter{}
	if err := WriteFrame(writer, FrameData, 1, []byte("short-write")); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(writer.Bytes(), want) {
		t.Fatalf("short write truncated frame: got %x want %x", writer.Bytes(), want)
	}

	for _, frame := range []Frame{
		{Type: FrameSettings, StreamID: 1},
		{Type: FrameTCPSyn, StreamID: 0},
		{Type: FrameData, StreamID: 2},
		{Type: FrameFin, StreamID: 0},
		{Type: FrameRST, StreamID: 2},
		{Type: FrameUDPAssoc, StreamID: 0},
		{Type: FrameDatagram, StreamID: 2, Payload: []byte{0, 0}},
		{Type: FrameWindowUpdate, StreamID: 2, Payload: []byte{0, 0, 0, 1}},
		{Type: FramePadding, StreamID: 1},
	} {
		if _, err := MarshalFrame(frame.Type, frame.StreamID, frame.Payload); err == nil {
			t.Fatalf("accepted known frame %#v with invalid stream ID", frame)
		}
	}
	if _, err := MarshalFrame(0x7f, 99, nil); err != nil {
		t.Fatalf("unknown frame must remain forward compatible: %v", err)
	}
	if _, err := BuildAuthFrame([]byte("psk"), make([]byte, 15), make([]byte, 32), 1, nil); err == nil {
		t.Fatal("expected short salt to fail")
	}
	if _, err := MarshalFrame(FrameData, 1, make([]byte, MaxDataPayload+1)); err == nil {
		t.Fatal("expected oversized DATA to fail")
	}
	for _, payload := range [][]byte{nil, []byte("dns"), bytes.Repeat([]byte{0xa5}, MaxUDPPayload)} {
		encoded, err := MarshalDatagram(payload)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := ParseDatagram(encoded)
		if err != nil || !bytes.Equal(decoded, payload) {
			t.Fatalf("DATAGRAM round trip = %d bytes, %v", len(decoded), err)
		}
	}
	if _, err := MarshalDatagram(make([]byte, MaxUDPPayload+1)); err == nil {
		t.Fatal("expected oversized DATAGRAM to fail")
	}
	for _, payload := range [][]byte{nil, {0}, {0, 2, 1}, {0, 0, 1}} {
		if _, err := ParseDatagram(payload); err == nil {
			t.Fatalf("malformed DATAGRAM %x accepted", payload)
		}
	}
	if _, err := ReadFrame(bytes.NewReader([]byte{FrameData, 0, 0})); err == nil {
		t.Fatal("expected truncated frame header to fail")
	}
	oversizedHeader := []byte{FramePadding, 0, 0, 0, 0, 0x10, 0, 1}
	if _, err := ReadFrame(bytes.NewReader(oversizedHeader)); err == nil {
		t.Fatal("expected oversized frame to fail")
	}

	for _, destination := range []Destination{
		{IP: netip.MustParseAddr("192.0.2.1"), Port: 80},
		{IP: netip.MustParseAddr("2001:db8::1"), Port: 443},
		{Host: "example.com", Port: 443},
	} {
		encoded := destination.MarshalBinary()
		decoded, err := ParseDestination(encoded)
		if err != nil {
			t.Fatal(err)
		}
		if decoded != destination {
			t.Fatalf("destination mismatch: got %#v want %#v", decoded, destination)
		}
	}
}

func mustDecodeHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func assertHex(t *testing.T, actual []byte, expected string) {
	t.Helper()
	if hex.EncodeToString(actual) != expected {
		t.Fatalf("unexpected bytes:\n got %x\nwant %s", actual, expected)
	}
}
