package artx

import (
	"net"
	"testing"
	"time"
)

func TestReadServerSettingsV2DrainsPaddingFrame(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	writeDone := make(chan error, 1)
	go func() {
		if err := WriteFrame(server, FrameSettings, 0, DefaultSettings(2).MarshalBinary()); err != nil {
			writeDone <- err
			return
		}
		writeDone <- WriteFrame(server, FramePadding, 0, make([]byte, 14))
	}()

	settings, err := readServerSettings(client, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := settings.Validate(2); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("profile-v2 padding flight was not drained")
	}
}

func TestReadServerSettingsV2AcceptsGreasedSettings(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	payload := append(DefaultSettings(2).MarshalBinary(), make([]byte, 6)...)
	writeDone := make(chan error, 1)
	go func() { writeDone <- WriteFrame(server, FrameSettings, 0, payload) }()

	settings, err := readServerSettings(client, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := settings.Validate(2); err != nil {
		t.Fatal(err)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
}

func TestReadServerSettingsV2RejectsUnexpectedSettingsLength(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	payload := append(DefaultSettings(2).MarshalBinary(), make([]byte, 12)...)
	writeDone := make(chan error, 1)
	go func() { writeDone <- WriteFrame(server, FrameSettings, 0, payload) }()

	if _, err := readServerSettings(client, 2); err == nil {
		t.Fatal("unexpected profile-v2 SETTINGS length was accepted")
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
}

func TestReadServerSettingsV3ReusesFailClosedFlightContract(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
		padding []byte
		wantErr bool
	}{
		{name: "greased", payload: append(DefaultSettings(3).MarshalBinary(), make([]byte, 6)...)},
		{name: "padded", payload: DefaultSettings(3).MarshalBinary(), padding: make([]byte, 14)},
		{name: "unexpected length", payload: append(DefaultSettings(3).MarshalBinary(), make([]byte, 12)...), wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, server := net.Pipe()
			t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
			writeDone := make(chan error, 1)
			go func() {
				if err := WriteFrame(server, FrameSettings, 0, test.payload); err != nil {
					writeDone <- err
					return
				}
				if test.padding != nil {
					writeDone <- WriteFrame(server, FramePadding, 0, test.padding)
					return
				}
				writeDone <- nil
			}()

			settings, err := readServerSettings(client, 3)
			if test.wantErr {
				if err == nil {
					t.Fatal("unexpected profile-v3 SETTINGS length was accepted")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if err := settings.Validate(3); err != nil {
					t.Fatal(err)
				}
			}
			if err := <-writeDone; err != nil {
				t.Fatal(err)
			}
		})
	}
}
