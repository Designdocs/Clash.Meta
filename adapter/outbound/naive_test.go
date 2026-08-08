package outbound

import (
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

func validNaiveOption() NaiveOption {
	return NaiveOption{
		Name:     "naive-node",
		Server:   "kr.example.com",
		Port:     12443,
		Username: "user",
		Password: "secret",
	}
}

func TestNewNaiveDefaults(t *testing.T) {
	naive, err := NewNaive(validNaiveOption())
	if err != nil {
		t.Fatal(err)
	}
	defer naive.Close()

	if naive.Type() != C.Naive {
		t.Fatalf("type is %s, want %s", naive.Type(), C.Naive)
	}
	// A Chrome ClientHello is the whole point of naive, so it has to hold even
	// when the profile stays silent about it.
	if naive.tlsConfig.ClientFingerprint != naiveDefaultFingerprint {
		t.Fatalf("client fingerprint is %q, want %q", naive.tlsConfig.ClientFingerprint, naiveDefaultFingerprint)
	}
	// naive is always TLS, and the certificate is checked against the server
	// host unless the profile overrides the SNI.
	if naive.tlsConfig.Host != "kr.example.com" {
		t.Fatalf("TLS host is %q, want the server host", naive.tlsConfig.Host)
	}
	if naive.tlsConfig.SkipCertVerify {
		t.Fatal("certificate verification must stay on by default")
	}
}

func TestNewNaiveHonoursSNIAndFingerprint(t *testing.T) {
	option := validNaiveOption()
	option.SNI = "front.example.com"
	option.ClientFingerprint = "firefox"
	option.SkipCertVerify = true

	naive, err := NewNaive(option)
	if err != nil {
		t.Fatal(err)
	}
	defer naive.Close()

	if naive.tlsConfig.Host != "front.example.com" {
		t.Fatalf("TLS host is %q, want the configured SNI", naive.tlsConfig.Host)
	}
	if naive.tlsConfig.ClientFingerprint != "firefox" {
		t.Fatalf("client fingerprint is %q, want the configured one", naive.tlsConfig.ClientFingerprint)
	}
	if !naive.tlsConfig.SkipCertVerify {
		t.Fatal("skip-cert-verify did not reach the TLS config")
	}
}

func TestNewNaiveAcceptsExplicitHTTP2(t *testing.T) {
	option := validNaiveOption()
	option.Protocol = naiveProtocolHTTP2
	naive, err := NewNaive(option)
	if err != nil {
		t.Fatal(err)
	}
	naive.Close()
}
