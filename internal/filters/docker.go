package filters

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/tinfoil-research/netfoil-trinity/internal/trie"
	"github.com/tinfoil-research/netfoil-trinity/internal/verbs"
)

var regexDockerImageName = regexp.MustCompile("^[a-z0-9-]+$")
var regexDockerVersion = regexp.MustCompile("^(latest|v[0-9]+(\\.[0-9]+)*|sha256:[a-f0-9]{64})$")
var regexDockerExpires = regexp.MustCompile("^[0-9]+$")
var regexDockerSignature = regexp.MustCompile("^[a-zA-Z0-9~_-]+$")
var regexDockerKeyPairID = regexp.MustCompile("^[A-Z0-9]+$")
var regexSHA256 = regexp.MustCompile("^[a-f0-9]{64}$")

type DockerFilter struct {
	imageTrie trie.Node
}

func NewDockerFilter(allowedImages []string) (*DockerFilter, error) {
	imageTrie := trie.Node{}
	for _, repo := range allowedImages {
		err := imageTrie.Insert(repo, nil)
		if err != nil {
			return nil, err
		}
	}

	return &DockerFilter{
		imageTrie: imageTrie,
	}, nil
}

func (f *DockerFilter) Transform(r *http.Request) (*http.Request, bool) {
	err := errOnNonEmptyBody(r)
	if err != nil {
		return nil, false
	}

	if r.Host == "registry-1.docker.io" {
		if f.verifyRegistry(r.RequestURI, r.Method) {
			return r, true
		}
	} else if r.Host == "auth.docker.io" {
		if f.verifyAuth(r.RequestURI, r.Method) {
			return r, true
		}
	} else if r.Host == "production.cloudfront.docker.com" {
		if verifyCloudfront(r.RequestURI, r.Method) {
			return r, true
		}
	}

	return nil, false
}

func (f *DockerFilter) verifyRegistry(urlString string, method string) bool {
	if !(method == string(verbs.GET) || method == string(verbs.HEAD)) {
		return false
	}

	releasesPrefix := "/v2/library/"
	if after, ok := strings.CutPrefix(urlString, releasesPrefix); ok {
		parts := strings.Split(after, "/")

		imageName := parts[0]
		t := parts[1]
		version := parts[2]

		if !regexDockerImageName.MatchString(imageName) {
			return false
		}

		_, found := f.imageTrie.Match([]byte(imageName))
		if !found {
			return false
		}

		if !(t == "manifests" || t == "blobs" || t == "referrers") {
			return false
		}

		if !regexDockerVersion.MatchString(version) {
			return false
		}

		return true
	}

	return false
}

func (f *DockerFilter) verifyAuth(urlString string, method string) bool {
	if method != string(verbs.GET) {
		return false
	}

	u, err := url.Parse(urlString)
	if err != nil {
		return false
	}

	if u.Path != "/token" {
		return false
	}

	q := u.Query()
	if len(q) != 2 {
		return false
	}

	scope := q.Get("scope")
	if scope == "" {
		return false
	}

	parts := strings.Split(scope, ":")
	if len(parts) != 3 {
		return false
	}

	if parts[0] != "repository" {
		return false
	}

	if parts[2] != "pull" {
		return false
	}

	imageName, ok := strings.CutPrefix(parts[1], "library/")
	if !ok {
		return false
	}

	if !regexDockerImageName.MatchString(imageName) {
		return false
	}

	_, found := f.imageTrie.Match([]byte(imageName))
	if !found {
		return false
	}

	service := q.Get("service")
	if service != "registry.docker.io" {
		return false
	}

	return true
}

func verifyCloudfront(urlString string, method string) bool {
	if method != string(verbs.GET) {
		return false
	}

	u, err := url.Parse(urlString)
	if err != nil {
		return false
	}

	pathPrefix := "/registry-v2/docker/registry/v2/blobs/sha256/"
	after, ok := strings.CutPrefix(u.Path, pathPrefix)
	if !ok {
		return false
	}

	pathParts := strings.Split(after, "/")
	if len(pathParts) != 3 {
		return false
	}

	if pathParts[2] != "data" {
		return false
	}

	hash := pathParts[1]
	if !regexSHA256.MatchString(hash) {
		return false
	}

	hashPrefix := pathParts[0]
	if len(hashPrefix) != 2 {
		return false
	}

	if !strings.HasPrefix(hash, hashPrefix) {
		return false
	}

	q := u.Query()
	if len(q) != 3 {
		return false
	}

	expires := q.Get("Expires")
	if expires == "" || !regexDockerExpires.MatchString(expires) {
		return false
	}

	signature := q.Get("Signature")
	if signature == "" || !regexDockerSignature.MatchString(signature) {
		return false
	}

	keyPairId := q.Get("Key-Pair-Id")
	if keyPairId == "" || !regexDockerKeyPairID.MatchString(keyPairId) {
		return false
	}

	return true
}
