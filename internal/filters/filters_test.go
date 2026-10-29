package filters

import "testing"

func TestRegexRange(t *testing.T) {
	if !regexHeaderRange.MatchString("bytes=0-") {
		t.Errorf("should match")
	}

	if !regexHeaderRange.MatchString("bytes=0-1") {
		t.Errorf("should match")
	}

	if !regexHeaderRange.MatchString("bytes=-1") {
		t.Errorf("should match")
	}

	if !regexHeaderRange.MatchString("bytes=0-,0-1,-1") {
		t.Errorf("should match")
	}
}
