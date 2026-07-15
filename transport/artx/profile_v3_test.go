package artx

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/metacubex/mihomo/transport/vmess"
	"github.com/metacubex/tls"
)

func TestDialContextProfileV3ReturnsProfileV3Settings(t *testing.T) {
	clientRaw, serverRaw := net.Pipe()
	serverDone := make(chan error, 1)
	serverConfig := testTLSConfig(t, tls.VersionTLS13, tls.VersionTLS13)
	go func() {
		defer serverRaw.Close()
		connection := tls.Server(serverRaw, serverConfig)
		if err := connection.Handshake(); err != nil {
			serverDone <- err
			return
		}
		if _, err := readRawAuth(connection); err != nil {
			serverDone <- err
			return
		}
		payload := append(DefaultSettings(3).MarshalBinary(), make([]byte, 6)...)
		if err := WriteFrame(connection, FrameSettings, 0, payload); err != nil {
			serverDone <- err
			return
		}
		settings, err := ReadFrame(connection)
		if err != nil || settings.Type != FrameSettings || settings.StreamID != 0 {
			serverDone <- errors.New("client profile-v3 SETTINGS required")
			return
		}
		parsed, err := ParseSettings(settings.Payload)
		if err != nil {
			serverDone <- err
			return
		}
		if err := parsed.Validate(3); err != nil {
			serverDone <- err
			return
		}
		syn, err := ReadFrame(connection)
		if err != nil || syn.Type != FrameTCPSyn || syn.StreamID != 1 {
			serverDone <- errors.New("client TCP_SYN required")
			return
		}
		serverDone <- nil
	}()

	connection, err := DialContext(context.Background(), clientRaw, ClientConfig{
		Password:       "secret",
		Profile:        "balanced",
		ProfileVersion: 3,
		TLSConfig: &vmess.TLSConfig{
			Host: "example.com", SkipCertVerify: true, ClientFingerprint: "chrome",
		},
	}, Destination{Host: "example.com", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	_ = connection.Close()
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}
