package adapter

import (
	"strings"
	"testing"
)

func TestArtXParserAcceptsOnlyBalancedProfileV2(t *testing.T) {
	balanced := validArtXMapping()
	balanced["profile-version"] = 2
	proxy, err := ParseProxy(balanced)
	if err != nil {
		t.Fatal(err)
	}
	proxy.Close()

	nonBalanced := validArtXMapping()
	nonBalanced["profile"] = "web"
	nonBalanced["profile-version"] = 2
	_, err = ParseProxy(nonBalanced)
	if err == nil || !strings.Contains(err.Error(), "balanced") {
		t.Fatalf("expected balanced profile error, got %v", err)
	}
}

func TestArtXParserAcceptsOnlyBalancedProfileV3(t *testing.T) {
	balanced := validArtXMapping()
	balanced["profile-version"] = 3
	proxy, err := ParseProxy(balanced)
	if err != nil {
		t.Fatal(err)
	}
	proxy.Close()

	nonBalanced := validArtXMapping()
	nonBalanced["profile"] = "web"
	nonBalanced["profile-version"] = 3
	_, err = ParseProxy(nonBalanced)
	if err == nil || !strings.Contains(err.Error(), "balanced") {
		t.Fatalf("expected balanced profile error, got %v", err)
	}
}
