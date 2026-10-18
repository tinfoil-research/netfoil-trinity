package filters

import "testing"

func TestDockerVersionRegex(t *testing.T) {
	if !regexDockerVersion.MatchString("latest") {
		t.Errorf("should match")
	}

	if !regexDockerVersion.MatchString("v0") {
		t.Errorf("should match")
	}

	if !regexDockerVersion.MatchString("v0.1") {
		t.Errorf("should match")
	}

	if !regexDockerVersion.MatchString("v0.1.2") {
		t.Errorf("should match")
	}

	if !regexDockerVersion.MatchString("sha256:0123456789abcdef000000000000000000000000000000000000000000000000") {
		t.Errorf("should match")
	}
}

func TestVerifyAuth(t *testing.T) {
	filter, err := NewDockerFilter([]string{"ubuntu"})
	if err != nil {
		t.Fatal(err)
	}

	if !filter.verifyAuth("/token?scope=repository%3Alibrary%2Fubuntu%3Apull&service=registry.docker.io", "GET") {
		t.Errorf("should verify")
	}
}

func TestVerifyCloudfront(t *testing.T) {
	if !verifyCloudfront("/registry-v2/docker/registry/v2/blobs/sha256/ab/abcdef0000000000000000000000000000000000000000000000000000000000/data?Expires=100&Signature=azAZ09~_-&Key-Pair-Id=AZ09", "GET") {
		t.Errorf("should verify")
	}
}

func TestHeaderAccept(t *testing.T) {
	if !regexDockerHeaderAccept.MatchString("application/vnd.docker.distribution.manifest.v2+json") {
		t.Errorf("should match")
	}

	if !regexDockerHeaderAccept.MatchString("application/vnd.in-toto+json") {
		t.Errorf("should match")
	}

	if !regexDockerHeaderAccept.MatchString("*/*") {
		t.Errorf("should match")
	}
}

func TestHeaderReferer(t *testing.T) {
	if !regexDockerHeaderReferer.MatchString("https://registry-1.docker.io/v2/library/ubuntu/blobs/sha256:abcdef0000000000000000000000000000000000000000000000000000000000") {
		t.Errorf("should match")
	}
}
