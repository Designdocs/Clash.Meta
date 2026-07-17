package artx

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"testing"
	"time"

	tlsC "github.com/metacubex/mihomo/component/tls"
	"github.com/metacubex/mihomo/transport/vmess"
	"github.com/metacubex/tls"
	"golang.org/x/net/http2"
)

const (
	wireV3VectorEnvelope           = "030010000f101112131415161718191a1b1c1d1e1f4a94d7419f1832b401020304030b6578616d706c652e6e657401bbf58a80358d4f712f4afdabbf35a721e63bd5becf1bcb6aad14df19af557a0e78"
	wireV3VectorAuthorization      = "Bearer AwAQAA8QERITFBUWFxgZGhscHR4fSpTXQZ8YMrQBAgMEAwtleGFtcGxlLm5ldAG79YqANY1PcS9K_au_Nach5jvVvs8by2qtFN8Zr1V6Dng"
	wireV3VectorAuthenticationInfo = "rspauth=\"6wsIUpP3Pep2k-fRL8Z5bT90wxRFcIW61aHo_DcbkEU\""
	wireV3TestTargetEOF            = "target-downlink-eof"
)

func TestWireV3AuthenticationVector(t *testing.T) {
	psk, exporter, salt, destination := wireV3VectorInputs()
	init, err := newWireV3ClientInit(psk, salt, exporter, "example.com:8443", "/", destination, 0x01020304)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := init.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(envelope); got != wireV3VectorEnvelope {
		t.Fatalf("ClientInit = %s", got)
	}
	if got := formatWireV3Authorization(init); got != wireV3VectorAuthorization {
		t.Fatalf("Authorization = %q", got)
	}

	parsed, candidate, err := parseWireV3Authorization(wireV3VectorAuthorization)
	if err != nil || !candidate {
		t.Fatalf("parse Authorization: candidate=%v err=%v", candidate, err)
	}
	if !parsed.Verify(psk, exporter, "example.com:8443", "/") {
		t.Fatal("valid ClientInit rejected")
	}
	if got := formatWireV3AuthenticationInfo(calculateWireV3ServerProof(psk, exporter, parsed.ClientTag, 200)); got != wireV3VectorAuthenticationInfo {
		t.Fatalf("Authentication-Info = %q", got)
	}
	if !verifyWireV3AuthenticationInfo(wireV3VectorAuthenticationInfo, psk, exporter, parsed.ClientTag, 200) {
		t.Fatal("valid server proof rejected")
	}
}

func TestWireV3AuthenticationFailsClosed(t *testing.T) {
	psk, exporter, _, _ := wireV3VectorInputs()
	parsed, candidate, err := parseWireV3Authorization(wireV3VectorAuthorization)
	if err != nil || !candidate {
		t.Fatal(err)
	}
	if parsed.Verify(psk, exporter, "other.example:8443", "/") {
		t.Fatal("authority mutation accepted")
	}
	if parsed.Verify(psk, exporter, "example.com:8443", "/other") {
		t.Fatal("path mutation accepted")
	}
	if verifyWireV3AuthenticationInfo(wireV3VectorAuthenticationInfo, psk, exporter, parsed.ClientTag, 201) {
		t.Fatal("status mutation accepted")
	}
	if _, candidate, err := parseWireV3Authorization("Basic abc"); err != nil || candidate {
		t.Fatalf("non-candidate header: candidate=%v err=%v", candidate, err)
	}
	if _, candidate, err := parseWireV3Authorization("Bearer !!!"); err == nil || !candidate {
		t.Fatalf("malformed candidate: candidate=%v err=%v", candidate, err)
	}

	envelope, _ := hex.DecodeString(wireV3VectorEnvelope)
	for _, mutation := range []struct {
		name   string
		offset int
	}{
		{name: "version", offset: 0},
		{name: "flags", offset: 1},
		{name: "salt length", offset: 2},
		{name: "destination length", offset: 4},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			mutated := bytes.Clone(envelope)
			mutated[mutation.offset]++
			if _, err := parseWireV3ClientInit(mutated); err == nil {
				t.Fatal("mutated envelope accepted")
			}
		})
	}
	mutated := bytes.Clone(envelope)
	mutated[len(mutated)-1] ^= 1
	mutatedInit, err := parseWireV3ClientInit(mutated)
	if err != nil {
		t.Fatal(err)
	}
	if mutatedInit.Verify(psk, exporter, "example.com:8443", "/") {
		t.Fatal("tag mutation accepted")
	}
}

func TestWireV3HTTP2TunnelEcho(t *testing.T) {
	clientRaw, serverRaw := net.Pipe()
	serverConfig := testTLSConfig(t, tls.VersionTLS13, tls.VersionTLS13)
	serverConfig.NextProtos = []string{http2.NextProtoTLS}
	serverDone := make(chan error, 1)
	go func() { serverDone <- runWireV3HTTP2TestServer(serverRaw, serverConfig, false, false) }()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	connection, err := DialContext(ctx, clientRaw, ClientConfig{
		Password:       "secret",
		Profile:        "balanced",
		ProfileVersion: 1,
		WireVersion:    3,
		Authority:      "example.com",
		TLSConfig: &vmess.TLSConfig{
			Host:              "example.com",
			SkipCertVerify:    true,
			ClientFingerprint: "chrome",
		},
	}, Destination{Host: "example.net", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("wire-v3 echo")
	if _, err := connection.Write(payload); err != nil {
		t.Fatal(err)
	}
	echo := make([]byte, len(payload))
	if _, err := io.ReadFull(connection, echo); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(echo, payload) {
		t.Fatalf("echo = %q", echo)
	}
	if err := connection.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("wire-v3 response close = %v, want EOF", err)
	}
	_ = connection.Close()
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("wire-v3 test server did not close")
	}
}

func TestWireV3ClientClosesOuterOnTargetDownloadEOF(t *testing.T) {
	clientRaw, serverRaw := net.Pipe()
	serverConfig := testTLSConfig(t, tls.VersionTLS13, tls.VersionTLS13)
	serverConfig.NextProtos = []string{http2.NextProtoTLS}
	serverDone := make(chan error, 1)
	go func() { serverDone <- runWireV3HTTP2TestServer(serverRaw, serverConfig, false, true) }()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	connection, err := DialContext(ctx, clientRaw, ClientConfig{
		Password: "secret", Profile: "balanced", ProfileVersion: 1, WireVersion: 3, Authority: "example.com",
		TLSConfig: &vmess.TLSConfig{Host: "example.com", SkipCertVerify: true, ClientFingerprint: "chrome"},
	}, Destination{Host: "example.net", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	downlink := make([]byte, len(wireV3TestTargetEOF))
	if _, err := io.ReadFull(connection, downlink); err != nil {
		t.Fatal(err)
	}
	if string(downlink) != wireV3TestTargetEOF {
		t.Fatalf("downlink = %q", downlink)
	}
	if _, err := connection.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("wire-v3 target EOF = %v, want EOF", err)
	}
	if _, err := connection.Write([]byte("late upload")); err == nil {
		t.Fatal("wire-v3 upload remained writable after target download EOF")
	}
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("wire-v3 outer connection remained open after target download EOF")
	}
}

func TestWireV3ClientRejectsWrongProof(t *testing.T) {
	clientRaw, serverRaw := net.Pipe()
	serverConfig := testTLSConfig(t, tls.VersionTLS13, tls.VersionTLS13)
	serverConfig.NextProtos = []string{http2.NextProtoTLS}
	serverDone := make(chan error, 1)
	go func() { serverDone <- runWireV3HTTP2TestServer(serverRaw, serverConfig, true, false) }()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	connection, err := DialContext(ctx, clientRaw, ClientConfig{
		Password: "secret", Profile: "balanced", ProfileVersion: 1, WireVersion: 3, Authority: "example.com",
		TLSConfig: &vmess.TLSConfig{Host: "example.com", SkipCertVerify: true, ClientFingerprint: "chrome"},
	}, Destination{Host: "example.net", Port: 443})
	if err == nil || connection != nil {
		t.Fatal("wire-v3 client accepted wrong server proof")
	}
	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("wrong-proof server did not close")
	}
}

func TestWireV3ClientRejectsWrongALPN(t *testing.T) {
	clientRaw, serverRaw := net.Pipe()
	serverConfig := testTLSConfig(t, tls.VersionTLS13, tls.VersionTLS13)
	serverDone := make(chan error, 1)
	go func() {
		connection := tls.Server(serverRaw, serverConfig)
		err := connection.Handshake()
		_ = connection.Close()
		serverDone <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	connection, err := DialContext(ctx, clientRaw, ClientConfig{
		Password: "secret", Profile: "balanced", ProfileVersion: 1, WireVersion: 3, Authority: "example.com",
		TLSConfig: &vmess.TLSConfig{Host: "example.com", SkipCertVerify: true, ClientFingerprint: "chrome"},
	}, Destination{Host: "example.net", Port: 443})
	if err == nil || connection != nil {
		t.Fatal("wire-v3 client accepted missing h2 ALPN")
	}
	<-serverDone
}

func runWireV3HTTP2TestServer(raw net.Conn, config *tls.Config, wrongProof, closeDownload bool) error {
	defer raw.Close()
	connection := tls.Server(raw, config)
	if err := connection.Handshake(); err != nil {
		return err
	}
	state := tlsC.GetTLSConnectionState(connection)
	exporter, err := state.ExportKeyingMaterial(wireV3ExporterLabel, nil, wireV3ExporterLength)
	if err != nil {
		return err
	}
	handlerStarted := make(chan struct{})
	handlerDone := make(chan error, 1)
	server := new(http2.Server)
	server.ServeConn(connection, &http2.ServeConnOpts{
		BaseConfig: &http.Server{ErrorLog: log.New(io.Discard, "", 0)},
		Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			close(handlerStarted)
			init, candidate, err := parseWireV3Authorization(request.Header.Get("Authorization"))
			if err != nil || !candidate || !init.Verify([]byte("secret"), exporter, request.Host, request.URL.Path) {
				handlerDone <- errors.New("invalid wire-v3 ClientInit")
				return
			}
			if _, err := ParseDestination(init.Destination); err != nil {
				handlerDone <- err
				return
			}
			proof := calculateWireV3ServerProof([]byte("secret"), exporter, init.ClientTag, http.StatusOK)
			if wrongProof {
				proof[0] ^= 1
			}
			writer.Header().Set("Authentication-Info", formatWireV3AuthenticationInfo(proof))
			writer.Header().Set("Content-Type", "application/octet-stream")
			writer.Header().Set("Cache-Control", "no-store")
			writer.WriteHeader(http.StatusOK)
			writer.(http.Flusher).Flush()
			if closeDownload {
				_, err = writer.Write([]byte(wireV3TestTargetEOF))
				handlerDone <- err
				return
			}
			_, err = io.Copy(wireV3TestFlushWriter{writer}, request.Body)
			handlerDone <- err
		}),
	})
	select {
	case <-handlerStarted:
		return <-handlerDone
	default:
		return nil
	}
}

type wireV3TestFlushWriter struct{ http.ResponseWriter }

func (writer wireV3TestFlushWriter) Write(payload []byte) (int, error) {
	written, err := writer.ResponseWriter.Write(payload)
	writer.ResponseWriter.(http.Flusher).Flush()
	return written, err
}

func wireV3VectorInputs() ([]byte, []byte, []byte, []byte) {
	exporter := make([]byte, wireV3ExporterLength)
	for index := range exporter {
		exporter[index] = byte(index)
	}
	salt := make([]byte, wireV3SaltLength)
	for index := range salt {
		salt[index] = byte(0x10 + index)
	}
	destination := append([]byte{0x03, 0x0b}, []byte("example.net")...)
	destination = append(destination, 0x01, 0xbb)
	return []byte("test-psk"), exporter, salt, destination
}
