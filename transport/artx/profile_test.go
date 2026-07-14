package artx

import "testing"

func TestValidateClientProfile(t *testing.T) {
	tests := []struct {
		name           string
		profile        string
		profileVersion uint32
		wantErr        bool
	}{
		{name: "v1 legacy direct client", profileVersion: 1},
		{name: "v1 named profile", profile: "web", profileVersion: 1},
		{name: "v2 balanced", profile: "balanced", profileVersion: 2},
		{name: "v2 non-balanced", profile: "media", profileVersion: 2, wantErr: true},
		{name: "unsupported version", profile: "balanced", profileVersion: 3, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateClientProfile(test.profile, test.profileVersion)
			if test.wantErr && err == nil {
				t.Fatal("invalid profile contract was accepted")
			}
			if !test.wantErr && err != nil {
				t.Fatal(err)
			}
		})
	}
}
