package config

import "testing"

// The client writes `tls-fragment` into config.yaml, so the key has to survive
// the trip from YAML through RawConfig into the General block the executor
// hands to the dialer. Anything less and the setting is silently inert.
func TestTLSFragmentSurvivesConfigParsing(t *testing.T) {
	raw, err := UnmarshalRawConfig([]byte("tls-fragment: true\ntls-fragment-delay: 25\n"))
	if err != nil {
		t.Fatalf("could not parse the config: %v", err)
	}
	if !raw.TLSFragment {
		t.Error("the raw config lost tls-fragment")
	}
	if raw.TLSFragmentDelay != 25 {
		t.Errorf("the raw config carries a delay of %d, want 25", raw.TLSFragmentDelay)
	}

	general, err := parseGeneral(raw)
	if err != nil {
		t.Fatalf("could not build the general block: %v", err)
	}
	if !general.TLSFragment {
		t.Error("the general block lost tls-fragment")
	}
	if general.TLSFragmentDelay != 25 {
		t.Errorf("the general block carries a delay of %d, want 25", general.TLSFragmentDelay)
	}
}

// A profile that never mentions the key must leave fragmentation off: every
// existing subscription is such a profile.
func TestTLSFragmentDefaultsOff(t *testing.T) {
	raw, err := UnmarshalRawConfig([]byte("mode: rule\n"))
	if err != nil {
		t.Fatalf("could not parse the config: %v", err)
	}
	if raw.TLSFragment {
		t.Error("fragmentation turned itself on for a profile that never asked")
	}
	if raw.TLSFragmentDelay != 0 {
		t.Errorf("the default delay is %d, want 0", raw.TLSFragmentDelay)
	}
}
