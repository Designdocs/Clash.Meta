package adapter

import (
	"strings"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

func TestArtXParser(t *testing.T) {
	mapping := validArtXMapping()
	proxy, err := ParseProxy(mapping)
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	if proxy.Type() != C.ArtX {
		t.Fatalf("unexpected type: %s", proxy.Type())
	}
	if proxy.SupportUDP() || proxy.SupportUOT() {
		t.Fatal("ArtX wire v1 must remain TCP-only")
	}
}

func TestArtXParserRejectsInvalidOptions(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value any
		want  string
	}{
		{name: "udp", key: "udp", value: true, want: "udp"},
		{name: "profile", key: "profile", value: "unknown", want: "profile"},
		{name: "profile version", key: "profile-version", value: 4, want: "profile-version"},
		{name: "missing fingerprint", key: "client-fingerprint", value: "", want: "client-fingerprint"},
		{name: "invalid fingerprint", key: "client-fingerprint", value: "artx", want: "client-fingerprint"},
		{name: "blank password", key: "password", value: " \t ", want: "password"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mapping := validArtXMapping()
			mapping[test.key] = test.value
			_, err := ParseProxy(mapping)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("expected %q error, got %v", test.want, err)
			}
		})
	}
}

func TestArtXNativeAnyTLSParserRegression(t *testing.T) {
	proxy, err := ParseProxy(map[string]any{
		"name":               "native-anytls",
		"type":               "anytls",
		"server":             "127.0.0.1",
		"port":               443,
		"password":           "secret",
		"client-fingerprint": "chrome",
		"udp":                true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	if proxy.Type() != C.AnyTLS || !proxy.SupportUDP() || !proxy.SupportUOT() {
		t.Fatal("native AnyTLS behavior changed")
	}
}

func validArtXMapping() map[string]any {
	return map[string]any{
		"name":               "artx",
		"type":               "artx",
		"server":             "127.0.0.1",
		"port":               443,
		"password":           "secret",
		"sni":                "example.com",
		"client-fingerprint": "chrome",
		"profile":            "balanced",
		"profile-version":    1,
	}
}
