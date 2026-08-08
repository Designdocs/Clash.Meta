package artx

import (
	"context"
	"encoding/hex"
	"errors"
	"net"
	"testing"
	"time"
)

func TestNativeUDPAuthenticationVector(t *testing.T) {
	psk := []byte("test-native-udp-psk")
	salt := decodeNativeUDPHex(t, "000102030405060708090a0b0c0d0e0f")
	exporter := decodeNativeUDPHex(t, "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")
	request := nativeUDPRequest{
		method:          "CONNECT",
		protocol:        "connect-udp",
		scheme:          "https",
		authority:       "edge.example.com:443",
		path:            "/.well-known/masque/udp/2001%3Adb8%3A%3A42/443/",
		capsuleProtocol: "?1",
	}
	authorization, err := newNativeUDPAuthorization(psk, salt, exporter, request, 123456)
	if err != nil {
		t.Fatal(err)
	}
	const wantAuthorization = "ArtX AQAAAQIDBAUGBwgJCgsMDQ4PuvhTdc0L_McAAeJAYdDGUluy7-jK4l-XcvJEIJL4f5q4ONwMbbWqgUEiWDM"
	if got := authorization.header(); got != wantAuthorization {
		t.Fatalf("authorization = %q, want %q", got, wantAuthorization)
	}
	const proof = `rspauth="yBw-OLgcAisFyLoduW64wDJL7IeWBs1gpzo9qlDQZQ8"`
	if !authorization.verifyServerProof(proof, psk, exporter, 200, request.capsuleProtocol) {
		t.Fatal("server proof did not verify")
	}
}

func TestNativeUDPReadDeadlineUsesDatagramContext(t *testing.T) {
	parent, cancelParent := context.WithCancel(context.Background())
	defer cancelParent()
	connection := &nativeUDPPacketConn{ctx: parent}
	deadline := time.Now().Add(20 * time.Millisecond)
	if err := connection.SetReadDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	receiveContext, cancel := connection.receiveContext()
	defer cancel()
	select {
	case <-receiveContext.Done():
		if !errors.Is(receiveContext.Err(), context.DeadlineExceeded) {
			t.Fatalf("receive context error = %v", receiveContext.Err())
		}
	case <-time.After(time.Second):
		t.Fatal("datagram receive deadline did not expire")
	}
}

func TestNativeUDPRejectsEmptyPayloadBeforeSending(t *testing.T) {
	remote := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 53}
	connection := &nativeUDPPacketConn{remote: remote}
	if _, err := connection.WriteTo(nil, remote); err == nil {
		t.Fatal("empty native UDP payload was accepted")
	}
}

func decodeNativeUDPHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}
