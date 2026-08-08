package adapter

import (
	"strings"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

func validNaiveMapping() map[string]any {
	return map[string]any{
		"name":     "naive-node",
		"type":     "naive",
		"server":   "kr.example.com",
		"port":     12443,
		"username": "user",
		"password": "secret",
		"sni":      "kr.example.com",
	}
}

func TestNaiveParser(t *testing.T) {
	proxy, err := ParseProxy(validNaiveMapping())
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()

	if proxy.Type() != C.Naive {
		t.Fatalf("unexpected type: %s", proxy.Type())
	}
	if proxy.Addr() != "kr.example.com:12443" {
		t.Fatalf("unexpected address: %s", proxy.Addr())
	}
	// UDP over naive is not carried yet, so nothing may advertise it.
	if proxy.SupportUDP() || proxy.SupportUOT() {
		t.Fatal("naive must not advertise UDP support")
	}
}

// A profile that asks for UDP still has to load: refusing the node would take
// the whole subscription down over a capability gap.
func TestNaiveParserKeepsNodeWhenUDPRequested(t *testing.T) {
	mapping := validNaiveMapping()
	mapping["udp"] = true
	proxy, err := ParseProxy(mapping)
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	if proxy.SupportUDP() {
		t.Fatal("naive advertised UDP it cannot carry")
	}
}

func TestNaiveParserAcceptsHTTP3(t *testing.T) {
	mapping := validNaiveMapping()
	mapping["protocol"] = "http3"
	proxy, err := ParseProxy(mapping)
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()

	if proxy.Type() != C.Naive {
		t.Fatalf("unexpected type: %s", proxy.Type())
	}
	// The address still reads as host:port even though the carrier is UDP.
	if proxy.Addr() != "kr.example.com:12443" {
		t.Fatalf("unexpected address: %s", proxy.Addr())
	}
	// HTTP/3 changes the carrier, not what naive can proxy: still no UDP.
	if proxy.SupportUDP() || proxy.SupportUOT() {
		t.Fatal("naive must not advertise UDP support")
	}
}

func TestNaiveParserRejectsInvalidOptions(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(mapping map[string]any)
		want   string
	}{
		{
			// Caught by the decoder before NewNaive runs, since the field
			// carries no omitempty.
			name:   "missing password",
			mutate: func(mapping map[string]any) { delete(mapping, "password") },
			want:   "unset fields: password",
		},
		{
			name:   "blank password",
			mutate: func(mapping map[string]any) { mapping["password"] = "   " },
			want:   "password is required",
		},
		{
			name:   "port out of range",
			mutate: func(mapping map[string]any) { mapping["port"] = 70000 },
			want:   "server or port",
		},
		{
			name:   "empty server",
			mutate: func(mapping map[string]any) { mapping["server"] = "" },
			want:   "server or port",
		},
		{
			name:   "unknown protocol",
			mutate: func(mapping map[string]any) { mapping["protocol"] = "http4" },
			want:   "unsupported naive protocol",
		},
		{
			name:   "unknown fingerprint",
			mutate: func(mapping map[string]any) { mapping["client-fingerprint"] = "netscape" },
			want:   "unsupported naive client-fingerprint",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mapping := validNaiveMapping()
			test.mutate(mapping)
			proxy, err := ParseProxy(mapping)
			if err == nil {
				proxy.Close()
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("got %v, want an error mentioning %q", err, test.want)
			}
		})
	}
}
