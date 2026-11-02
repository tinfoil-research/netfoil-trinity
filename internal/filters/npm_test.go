package filters

import "testing"

func TestNPMRegex(t *testing.T) {
	if !regexNPMHeaderPacoteVersion.MatchString("12.3.4") {
		t.Errorf("should match")
	}

	if !regexNPMHeaderPacoteReqType.MatchString("packument") {
		t.Errorf("should match")
	}

	if !regexNPMHeaderPacoteReqType.MatchString("tarball") {
		t.Errorf("should match")
	}

	if !regexNPMHeaderPacotePkgId.MatchString("registry:test") {
		t.Errorf("should match")
	}

	if !regexNPMHeaderPacotePkgId.MatchString("remote:test@https://registry.npmjs.org/test/-/test-1.2.3.tgz") {
		t.Errorf("should match")
	}

	if !regexNPMHeaderPacotePkgId.MatchString("remote:@test/test@https://registry.npmjs.org/@test/test/-/test-1.2.3.tgz") {
		t.Errorf("should match")
	}

	if !regexNPMHeaderPacotePkgId.MatchString("registry:@test/test") {
		t.Errorf("should match")
	}

	if !regexNPMHeaderConnection.MatchString("keep-alive") {
		t.Errorf("should match")
	}

	if !regexNPMHeaderAccept.MatchString("application/vnd.npm.install-v1+json; q=1.0") {
		t.Errorf("should match")
	}

	if !regexNPMHeaderAccept.MatchString("application/json; q=0.8") {
		t.Errorf("should match")
	}

	if !regexNPMHeaderAccept.MatchString("*/*") {
		t.Errorf("should match")
	}

	if !regexNPMHeaderAcceptEncoding.MatchString("gzip") {
		t.Errorf("should match")
	}

	if !regexNPMHeaderAcceptEncoding.MatchString("deflate") {
		t.Errorf("should match")
	}

	if !regexNPMHeaderAuthType.MatchString("web") {
		t.Errorf("should match")
	}

	if !regexNPMHeaderCommand.MatchString("install") {
		t.Errorf("should match")
	}

	if !regexNPMHeaderUserAgent.MatchString("npm/1.2.3 node/v1.2.3") {
		t.Errorf("should match")
	}

	if !regexNPMHeaderIfNoneMatch.MatchString("W/\"az09\"") {
		t.Errorf("should match")
	}

	if !regexNPMHeaderIfModifiedSince.MatchString("Mon, 01 Jan 2000 01:23:45 UTC") {
		t.Errorf("should match")
	}

	if !regexNPMHeaderPacoteIntegrity.MatchString("sha512-azAZ/09==") {
		t.Errorf("should match")
	}
}
