package filters

import "testing"

func TestDebianPath(t *testing.T) {
	if !regexDebianPath.MatchString("InRelease") {
		t.Errorf("failed to match")
	}

	if !regexDebianPath.MatchString("main/source/Sources.xz") {
		t.Errorf("failed to match")
	}

	if !regexDebianPath.MatchString("main/dep11/Components-amd64.yml") {
		t.Errorf("failed to match")
	}

	if !regexDebianPath.MatchString("main/dep11/Components-amd64.yml.gz") {
		t.Errorf("failed to match")
	}

	if !regexDebianPath.MatchString("main/dep11/icons-48x48.tar.gz") {
		t.Errorf("failed to match")
	}
}
