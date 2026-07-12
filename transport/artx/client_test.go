package artx

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"testing"
	"time"

	tlsC "github.com/metacubex/mihomo/component/tls"
	"github.com/metacubex/mihomo/transport/vmess"
	"github.com/metacubex/tls"
)

func TestArtXTLSHandshakeAndConnection(t *testing.T) {
	clientRaw, serverRaw := net.Pipe()
	serverConfig := testTLSConfig(t, tls.VersionTLS13, tls.VersionTLS13)
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- runTestServer(serverRaw, serverConfig, []serverAction{echoUntilFin})
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	connection, err := DialContext(ctx, clientRaw, ClientConfig{
		Password:       "secret",
		ProfileVersion: 1,
		TLSConfig: &vmess.TLSConfig{
			Host:              "example.com",
			SkipCertVerify:    true,
			ClientFingerprint: "chrome",
		},
	}, Destination{Host: "example.com", Port: 443})
	if err != nil {
		t.Fatal(err)
	}

	payload := bytes.Repeat([]byte("x"), int(InitialStreamWindow)+MaxDataPayload)
	writeDone := make(chan error, 1)
	go func() {
		_, err := connection.Write(payload)
		writeDone <- err
	}()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(connection, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("bidirectional DATA mismatch")
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	closer := connection.(interface{ CloseWrite() error })
	if err := closer.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if err := closer.CloseWrite(); err != nil {
		t.Fatalf("second CloseWrite must be harmless: %v", err)
	}
	if _, err := connection.Write([]byte("after-close-write")); err == nil {
		t.Fatal("Write succeeded after CloseWrite")
	}
	if _, err := connection.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("server FIN = %v, want EOF", err)
	}
	_ = connection.Close()
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestArtXRejectsTLS12(t *testing.T) {
	clientRaw, serverRaw := net.Pipe()
	serverDone := make(chan error, 1)
	go func() {
		server := tls.Server(serverRaw, testTLSConfig(t, tls.VersionTLS12, tls.VersionTLS12))
		serverDone <- server.Handshake()
		_ = server.Close()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := DialContext(ctx, clientRaw, ClientConfig{
		Password: "secret", ProfileVersion: 1,
		TLSConfig: &vmess.TLSConfig{Host: "example.com", SkipCertVerify: true, ClientFingerprint: "chrome"},
	}, Destination{Host: "example.com", Port: 443})
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("TLS 1.3")) {
		t.Fatalf("expected TLS 1.3 error, got %v", err)
	}
	_ = <-serverDone
}

func TestArtXVMessTLSExporterOptIn(t *testing.T) {
	for _, test := range []struct {
		name    string
		disable bool
		wantErr bool
	}{
		{name: "native preset", wantErr: true},
		{name: "artx opt-in", disable: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			clientRaw, serverRaw := net.Pipe()
			serverDone := make(chan error, 1)
			go func() {
				server := tls.Server(serverRaw, testTLSConfig(t, tls.VersionTLS13, tls.VersionTLS13))
				serverDone <- server.Handshake()
				_ = server.Close()
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			connection, err := vmess.StreamTLSConn(ctx, clientRaw, &vmess.TLSConfig{
				Host: "example.com", SkipCertVerify: true, ClientFingerprint: "chrome",
				DisableRenegotiation: test.disable,
			})
			if err != nil {
				t.Fatal(err)
			}
			state := tlsC.GetTLSConnectionState(connection)
			_, exportErr := state.ExportKeyingMaterial(exporterLabel, nil, exporterLength)
			if (exportErr != nil) != test.wantErr {
				t.Fatalf("ExportKeyingMaterial error = %v, wantErr %v", exportErr, test.wantErr)
			}
			_ = clientRaw.Close()
			_ = serverRaw.Close()
			_ = <-serverDone
		})
	}
}

func TestArtXUnknownFrameIgnoredAndKnownOrderRejected(t *testing.T) {
	for _, test := range []struct {
		name    string
		actions []serverAction
		want    string
	}{
		{name: "rst", actions: []serverAction{sendRST}, want: "reset"},
		{name: "settings after open", actions: []serverAction{sendSettings}, want: "unexpected"},
	} {
		t.Run(test.name, func(t *testing.T) {
			connection, serverDone := dialTestConnection(t, test.actions)
			_, err := connection.Read(make([]byte, 1))
			if err == nil || !bytes.Contains([]byte(err.Error()), []byte(test.want)) {
				t.Fatalf("Read error = %v, want %q", err, test.want)
			}
			if test.name == "rst" {
				if _, err := connection.Write([]byte("must fail")); err == nil {
					t.Fatal("RST did not terminate the write direction")
				}
			}
			_ = connection.Close()
			_ = <-serverDone
		})
	}

	connection, serverDone := dialTestConnection(t, []serverAction{sendUnknownThenData})
	buffer := make([]byte, 2)
	if _, err := io.ReadFull(connection, buffer); err != nil || string(buffer) != "ok" {
		t.Fatalf("unknown frame handling = %q, %v", buffer, err)
	}
	_ = connection.Close()
	_ = <-serverDone
}

func TestArtXTargetFINKeepsClientWriteOpen(t *testing.T) {
	connection, serverDone := dialTestConnection(t, []serverAction{targetFinThenReadClient})
	if _, err := connection.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("target FIN = %v, want EOF", err)
	}
	if _, err := connection.Write([]byte("after-fin")); err != nil {
		t.Fatalf("write after target FIN: %v", err)
	}
	if err := connection.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	_ = connection.Close()
}

func TestArtXContextCancellationInterruptsHandshake(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	clientRaw, serverRaw := net.Pipe()
	done := make(chan error, 1)
	go func() {
		_, err := DialContext(ctx, clientRaw, ClientConfig{
			Password: "secret", ProfileVersion: 1,
			TLSConfig: &vmess.TLSConfig{Host: "example.com", SkipCertVerify: true, ClientFingerprint: "chrome"},
		}, Destination{Host: "example.com", Port: 443})
		done <- err
	}()
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled handshake succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled handshake did not return")
	}
	_ = serverRaw.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.Copy(io.Discard, serverRaw); err != nil && !errors.Is(err, net.ErrClosed) {
		if netError, ok := err.(net.Error); ok && netError.Timeout() {
			t.Fatal("cancelled handshake left raw connection open")
		}
	}
	_ = serverRaw.Close()
}

func TestArtXCloseDoesNotWaitForFINWrite(t *testing.T) {
	client, server := net.Pipe()
	connection := NewConn(client)
	done := make(chan error, 1)
	go func() { done <- connection.Close() }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close blocked trying to write FIN")
	}
	_ = server.Close()
}

func TestArtXTransportRejectsBlankPassword(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	_, err := DialContext(context.Background(), client, ClientConfig{
		Password: " \t", ProfileVersion: 1, TLSConfig: &vmess.TLSConfig{ClientFingerprint: "chrome"},
	}, Destination{Host: "example.com", Port: 443})
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("password")) {
		t.Fatalf("blank password error = %v", err)
	}
}

func TestArtXReceiveWindowAccounting(t *testing.T) {
	window := newReceiveWindow()
	if err := window.consume(int(InitialStreamWindow) + 1); err == nil {
		t.Fatal("peer receive-window overflow accepted")
	}
	if err := window.consume(MaxDataPayload); err != nil {
		t.Fatal(err)
	}
	if err := window.restore(MaxDataPayload); err != nil {
		t.Fatal(err)
	}
	if err := window.restore(1); err == nil {
		t.Fatal("receive-window over-replenishment accepted")
	}
}

func TestArtXPeerDataBeforeWindowUpdateDoesNotDeadlockWriteFirst(t *testing.T) {
	payload := bytes.Repeat([]byte("w"), int(InitialStreamWindow)+MaxDataPayload)
	connection, serverDone := dialTestConnection(t, []serverAction{func(server net.Conn) error {
		received := 0
		for received < int(InitialStreamWindow) {
			frame, err := ReadFrame(server)
			if err != nil {
				return err
			}
			if frame.Type == FrameData {
				received += len(frame.Payload)
			}
		}
		if err := WriteFrame(server, FrameData, 1, []byte("early")); err != nil {
			return err
		}
		update := make([]byte, 4)
		binary.BigEndian.PutUint32(update, MaxDataPayload)
		if err := WriteFrame(server, FrameWindowUpdate, 0, update); err != nil {
			return err
		}
		if err := WriteFrame(server, FrameWindowUpdate, 1, update); err != nil {
			return err
		}
		for received < len(payload) {
			frame, err := ReadFrame(server)
			if err != nil {
				return err
			}
			if frame.Type == FrameData {
				received += len(frame.Payload)
			}
		}
		return WriteFrame(server, FrameFin, 1, nil)
	}})
	writeDone := make(chan error, 1)
	go func() {
		_, err := connection.Write(payload)
		writeDone <- err
	}()
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		_ = connection.Close()
		t.Fatal("client Write deadlocked before application Read")
	}
	early := make([]byte, 5)
	if _, err := io.ReadFull(connection, early); err != nil || string(early) != "early" {
		t.Fatalf("early peer DATA = %q, %v", early, err)
	}
	if err := <-serverDone; err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
	_ = connection.Close()
}

func TestArtXFINPreservesBufferedDataAfterTransportClose(t *testing.T) {
	payload := bytes.Repeat([]byte("f"), 2*MaxDataPayload)
	connection, serverDone := dialTestConnection(t, []serverAction{func(server net.Conn) error {
		for offset := 0; offset < len(payload); offset += MaxDataPayload {
			if err := WriteFrame(server, FrameData, 1, payload[offset:offset+MaxDataPayload]); err != nil {
				return err
			}
		}
		return WriteFrame(server, FrameFin, 1, nil)
	}})
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	var received bytes.Buffer
	buffer := make([]byte, 1024)
	for {
		read, err := connection.Read(buffer)
		received.Write(buffer[:read])
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("buffered Read failed after FIN: %v", err)
		}
	}
	if !bytes.Equal(received.Bytes(), payload) {
		t.Fatalf("buffered DATA length = %d, want %d", received.Len(), len(payload))
	}
	artxConnection := connection.(*Conn)
	for name, done := range map[string]<-chan struct{}{
		"frame reader":   artxConnection.readDone,
		"control writer": artxConnection.controlDone,
	} {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatalf("%s did not stop after terminal FIN", name)
		}
	}
	_ = connection.Close()
}

func TestArtXWriteDeadlineInterruptsWindowWait(t *testing.T) {
	connection, serverDone := dialTestConnection(t, []serverAction{func(server net.Conn) error {
		for {
			if _, err := ReadFrame(server); err != nil {
				return err
			}
		}
	}})
	writeDone := make(chan error, 1)
	go func() {
		_, err := connection.Write(bytes.Repeat([]byte("x"), int(InitialStreamWindow)+1))
		writeDone <- err
	}()
	time.Sleep(20 * time.Millisecond)
	if err := connection.SetWriteDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-writeDone:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("Write error = %v, want deadline exceeded", err)
		}
	case <-time.After(time.Second):
		_ = connection.Close()
		t.Fatal("write deadline did not interrupt flow-control wait")
	}
	_ = connection.Close()
	_ = <-serverDone
}

func TestArtXTransportRejectsInvalidProfileAndFingerprint(t *testing.T) {
	tests := []struct {
		name        string
		profile     uint32
		fingerprint string
		want        string
	}{
		{name: "profile version", profile: 2, fingerprint: "chrome", want: "profile"},
		{name: "blank fingerprint", profile: 1, fingerprint: " ", want: "fingerprint"},
		{name: "invalid fingerprint", profile: 1, fingerprint: "artx", want: "fingerprint"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			_, err := DialContext(ctx, client, ClientConfig{
				Password: "secret", ProfileVersion: test.profile,
				TLSConfig: &vmess.TLSConfig{Host: "example.com", SkipCertVerify: true, ClientFingerprint: test.fingerprint},
			}, Destination{Host: "example.com", Port: 443})
			if err == nil || !bytes.Contains([]byte(err.Error()), []byte(test.want)) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestArtXWindowUpdateFollowsApplicationRead(t *testing.T) {
	dataSent := make(chan struct{})
	noEarlyUpdate := make(chan struct{})
	connection, serverDone := dialTestConnection(t, []serverAction{func(server net.Conn) error {
		if err := WriteFrame(server, FrameData, 1, []byte("0123456789")); err != nil {
			return err
		}
		close(dataSent)
		if err := server.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
			return err
		}
		if frame, err := ReadFrame(server); err == nil {
			return errors.New("WINDOW_UPDATE sent before application Read: " + string(rune(frame.Type)))
		} else if netError, ok := err.(net.Error); !ok || !netError.Timeout() {
			return err
		}
		if err := server.SetReadDeadline(time.Time{}); err != nil {
			return err
		}
		close(noEarlyUpdate)
		for _, streamID := range []uint32{0, 1} {
			frame, err := ReadFrame(server)
			if err != nil {
				return err
			}
			if frame.Type != FrameWindowUpdate || frame.StreamID != streamID || binary.BigEndian.Uint32(frame.Payload) != 4 {
				return errors.New("WINDOW_UPDATE did not match application consumption")
			}
		}
		return nil
	}})
	<-dataSent
	<-noEarlyUpdate
	buffer := make([]byte, 4)
	if _, err := io.ReadFull(connection, buffer); err != nil {
		t.Fatal(err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	_ = connection.Close()
}

func TestArtXRSTDiscardsBufferedData(t *testing.T) {
	connection, serverDone := dialTestConnection(t, []serverAction{func(server net.Conn) error {
		if err := WriteFrame(server, FrameData, 1, []byte("stale")); err != nil {
			return err
		}
		return WriteFrame(server, FrameRST, 1, []byte{1})
	}})
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	buffer := make([]byte, 5)
	if _, err := connection.Read(buffer); err == nil || !bytes.Contains([]byte(err.Error()), []byte("reset")) {
		t.Fatalf("Read after RST = %q, %v; want immediate reset", buffer, err)
	}
	_ = connection.Close()
}

type serverAction func(net.Conn) error

func echoUntilFin(connection net.Conn) error {
	for {
		frame, err := ReadFrame(connection)
		if err != nil {
			return err
		}
		switch frame.Type {
		case FrameData:
			update := make([]byte, 4)
			binary.BigEndian.PutUint32(update, uint32(len(frame.Payload)))
			if err := WriteFrame(connection, FrameWindowUpdate, 0, update); err != nil {
				return err
			}
			if err := WriteFrame(connection, FrameWindowUpdate, 1, update); err != nil {
				return err
			}
			if err := WriteFrame(connection, FrameData, 1, frame.Payload); err != nil {
				return err
			}
		case FrameWindowUpdate:
			// Client replenishes downlink credit after application reads.
		case FrameFin:
			return WriteFrame(connection, FrameFin, 1, nil)
		default:
			return errors.New("unexpected client frame")
		}
	}
}

func sendRST(connection net.Conn) error {
	return WriteFrame(connection, FrameRST, 1, []byte{1})
}

func sendSettings(connection net.Conn) error {
	return WriteFrame(connection, FrameSettings, 0, DefaultSettings(1).MarshalBinary())
}

func sendUnknownThenData(connection net.Conn) error {
	if err := WriteFrame(connection, 0x7f, 99, []byte("ignored")); err != nil {
		return err
	}
	if err := WriteFrame(connection, FrameData, 1, []byte("ok")); err != nil {
		return err
	}
	return WriteFrame(connection, FrameFin, 1, nil)
}

func targetFinThenReadClient(connection net.Conn) error {
	if err := WriteFrame(connection, FrameFin, 1, nil); err != nil {
		return err
	}
	data, err := ReadFrame(connection)
	if err != nil || data.Type != FrameData || string(data.Payload) != "after-fin" {
		return errors.New("client DATA missing after target FIN")
	}
	fin, err := ReadFrame(connection)
	if err != nil || fin.Type != FrameFin {
		return errors.New("client FIN missing after target FIN")
	}
	return nil
}

func dialTestConnection(t *testing.T, actions []serverAction) (net.Conn, <-chan error) {
	t.Helper()
	return dialTestConnectionContext(t, context.Background(), actions)
}

func dialTestConnectionContext(t *testing.T, ctx context.Context, actions []serverAction) (net.Conn, <-chan error) {
	t.Helper()
	clientRaw, serverRaw := net.Pipe()
	serverDone := make(chan error, 1)
	serverConfig := testTLSConfig(t, tls.VersionTLS13, tls.VersionTLS13)
	go func() { serverDone <- runTestServer(serverRaw, serverConfig, actions) }()
	connection, err := DialContext(ctx, clientRaw, ClientConfig{
		Password: "secret", ProfileVersion: 1,
		TLSConfig: &vmess.TLSConfig{Host: "example.com", SkipCertVerify: true, ClientFingerprint: "chrome"},
	}, Destination{Host: "example.com", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	return connection, serverDone
}

func runTestServer(raw net.Conn, config *tls.Config, actions []serverAction) error {
	defer raw.Close()
	connection := tls.Server(raw, config)
	if err := connection.Handshake(); err != nil {
		return err
	}
	state := tlsC.GetTLSConnectionState(connection)
	exporter, err := state.ExportKeyingMaterial(exporterLabel, nil, exporterLength)
	if err != nil {
		return err
	}
	auth, err := readRawAuth(connection)
	if err != nil {
		return err
	}
	bucket := binary.BigEndian.Uint32(auth[26:30])
	want, err := BuildAuthFrame([]byte("secret"), auth[2:18], exporter, bucket, nil)
	if err != nil || !bytes.Equal(auth, want) {
		return errors.New("invalid client AUTH")
	}
	if err := WriteFrame(connection, FrameSettings, 0, DefaultSettings(1).MarshalBinary()); err != nil {
		return err
	}
	settings, err := ReadFrame(connection)
	if err != nil || settings.Type != FrameSettings || settings.StreamID != 0 {
		return errors.New("client SETTINGS required")
	}
	syn, err := ReadFrame(connection)
	if err != nil || syn.Type != FrameTCPSyn || syn.StreamID != 1 {
		return errors.New("client TCP_SYN required")
	}
	if _, err := ParseDestination(syn.Payload); err != nil {
		return err
	}
	for _, action := range actions {
		if err := action(connection); err != nil {
			return err
		}
	}
	if len(actions) == 0 {
		_, err = io.Copy(io.Discard, connection)
	}
	return err
}

func readRawAuth(reader io.Reader) ([]byte, error) {
	prefix := make([]byte, 2)
	if _, err := io.ReadFull(reader, prefix); err != nil {
		return nil, err
	}
	if prefix[0] != FrameAuth || prefix[1] != 16 {
		return nil, errors.New("invalid AUTH prefix")
	}
	rest := make([]byte, int(prefix[1])+46)
	if _, err := io.ReadFull(reader, rest); err != nil {
		return nil, err
	}
	return append(prefix, rest...), nil
}

func testTLSConfig(t *testing.T, minVersion, maxVersion uint16) *tls.Config {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "example.com"},
		DNSNames: []string{"example.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: minVersion, MaxVersion: maxVersion}
}
