package tlsfragment

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"
)

type recordingConn struct {
	net.Conn

	writes  [][]byte
	failOn  int
	failErr error
}

func (c *recordingConn) Write(b []byte) (int, error) {
	if c.failErr != nil && len(c.writes) == c.failOn {
		return 0, c.failErr
	}
	c.writes = append(c.writes, append([]byte(nil), b...))
	return len(b), nil
}

func TestConnFragmentsTheFirstWriteOnly(t *testing.T) {
	hello := realClientHello(t, "campus.example.com")
	inner := &recordingConn{}
	conn := NewConn(inner, 0)

	n, err := conn.Write(hello)
	if err != nil {
		t.Fatalf("writing the hello failed: %v", err)
	}
	if n != len(hello) {
		t.Errorf("Write returned %d, want the %d bytes it was handed", n, len(hello))
	}
	if len(inner.writes) != 2 {
		t.Fatalf("the hello went out in %d writes, want 2", len(inner.writes))
	}

	payload := []byte("application data")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("writing after the handshake failed: %v", err)
	}
	if len(inner.writes) != 3 {
		t.Fatalf("got %d writes in total, want 3", len(inner.writes))
	}
	if !bytes.Equal(inner.writes[2], payload) {
		t.Error("the write after the handshake was not passed through untouched")
	}
}

func TestConnPassesThroughNonHandshakeTraffic(t *testing.T) {
	payload := []byte{0x17, 0x03, 0x03, 0x00, 0x02, 0xAA, 0xBB}
	inner := &recordingConn{}
	conn := NewConn(inner, 0)

	n, err := conn.Write(payload)
	if err != nil {
		t.Fatalf("write failed: %v", err)
	}
	if n != len(payload) {
		t.Errorf("Write returned %d, want %d", n, len(payload))
	}
	if len(inner.writes) != 1 || !bytes.Equal(inner.writes[0], payload) {
		t.Error("a buffer that is not a ClientHello should reach the socket unchanged")
	}
}

func TestConnReportsWriteFailures(t *testing.T) {
	hello := realClientHello(t, "campus.example.com")
	wantErr := errors.New("connection reset")

	for _, failOn := range []int{0, 1} {
		inner := &recordingConn{failOn: failOn, failErr: wantErr}
		conn := NewConn(inner, 0)

		if _, err := conn.Write(hello); !errors.Is(err, wantErr) {
			t.Errorf("failing on record %d returned %v, want %v", failOn, err, wantErr)
		}
	}
}

func TestConnDelaySeparatesTheRecords(t *testing.T) {
	hello := realClientHello(t, "campus.example.com")
	inner := &recordingConn{}
	conn := NewConn(inner, 20*time.Millisecond)

	start := time.Now()
	if _, err := conn.Write(hello); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	elapsed := time.Since(start)

	if len(inner.writes) != 2 {
		t.Fatalf("got %d writes, want 2", len(inner.writes))
	}
	if elapsed < 20*time.Millisecond {
		t.Errorf("the records went out in %v, too fast to have been separated", elapsed)
	}
}

// TestConnHandshakesAgainstRealServer is the one that matters: a split
// ClientHello must still be a legal ClientHello, so a real TLS server has to
// accept it and finish the handshake.
func TestConnHandshakesAgainstRealServer(t *testing.T) {
	certificate := selfSignedCert(t)

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{certificate},
	})
	if err != nil {
		t.Fatalf("could not listen: %v", err)
	}
	defer listener.Close()

	served := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			served <- err
			return
		}
		defer conn.Close()
		served <- conn.(*tls.Conn).Handshake()
	}()

	for _, delay := range []time.Duration{0, 5 * time.Millisecond} {
		raw, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			t.Fatalf("could not dial: %v", err)
		}

		client := tls.Client(NewConn(raw, delay), &tls.Config{
			ServerName: "campus.example.com",
			RootCAs:    certPool(t, certificate),
		})
		if err := client.Handshake(); err != nil {
			t.Fatalf("handshake through a %v-delayed fragmenting conn failed: %v", delay, err)
		}
		client.Close()

		if err := <-served; err != nil {
			t.Fatalf("the server rejected the fragmented hello: %v", err)
		}

		go func() {
			conn, err := listener.Accept()
			if err != nil {
				served <- err
				return
			}
			defer conn.Close()
			served <- conn.(*tls.Conn).Handshake()
		}()
	}
}

func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("could not generate a key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "campus.example.com"},
		DNSNames:     []string{"campus.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("could not create a certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func certPool(t *testing.T, certificate tls.Certificate) *x509.CertPool {
	t.Helper()

	parsed, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatalf("could not parse the certificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	return pool
}

func TestConnUnwrapsToTheRealSocket(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	conn := NewConn(client, 0)
	if conn.Upstream() != client {
		t.Error("Upstream did not hand back the wrapped connection")
	}
}
