package filters

import "testing"

func TestGoVersion(t *testing.T) {
	if !regexGoVersion.MatchString("v0.0.1") {
		t.Errorf("should match")
	}

	if !regexGoVersion.MatchString("v0.0.0-20260102123456-aabbccddeeff") {
		t.Errorf("should match")
	}
}

func TestGoTilePath(t *testing.T) {
	if !regexGoTilePath.MatchString("/tile/0/1/002.p/34") {
		t.Errorf("should match")
	}

	if !regexGoTilePath.MatchString("/tile/0/1/x002/003.p/456") {
		t.Errorf("should match")
	}
}
