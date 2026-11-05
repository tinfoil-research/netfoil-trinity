package filters

import "testing"

func TestFedoraVersionRegex(t *testing.T) {
	if !regexFedoraVersion.MatchString("1:0.1.2-1") {
		t.Errorf("should match")
	}

	if !regexFedoraVersion.MatchString("1.2^az09.az09-1") {
		t.Errorf("should match")
	}

	if !regexFedoraVersion.MatchString("1.2+az09.az09-1") {
		t.Errorf("should match")
	}

	if !regexFedoraVersion.MatchString("1.2.3.p4-5") {
		t.Errorf("should match")
	}

	if !regexFedoraVersion.MatchString("1-1.2.az09") {
		t.Errorf("should match")
	}

	if !regexFedoraVersion.MatchString("1.2_3.4.5-1.az09") {
		t.Errorf("should match")
	}
}
