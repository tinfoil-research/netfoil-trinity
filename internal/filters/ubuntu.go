package filters

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/tinfoil-research/netfoil-trinity/internal/trie"
	"github.com/tinfoil-research/netfoil-trinity/internal/verbs"
)

type UbuntuFilter struct {
	packageTrie    trie.Node
	allowedHeaders map[string]*regexp.Regexp
	host           string
	pathPrefix     string
	components     map[string]struct{}
	suites         map[string]struct{}
}

func NewUbuntuFilter(host string, pathPrefix string, components []string, suites []string, allowedPackages []string) (*UbuntuFilter, error) {
	packageTrie := trie.Node{}
	for _, repo := range allowedPackages {
		err := packageTrie.Insert(repo, nil)
		if err != nil {
			return nil, err
		}
	}

	componentsMap := make(map[string]struct{})
	for _, component := range components {
		componentsMap[component] = struct{}{}
	}

	suitesMap := make(map[string]struct{})
	for _, suite := range suites {
		suitesMap[suite] = struct{}{}
	}

	allowedHeaders := debianAllowedHeaders()
	return &UbuntuFilter{
		packageTrie:    packageTrie,
		allowedHeaders: allowedHeaders,
		host:           host,
		pathPrefix:     pathPrefix,
		components:     componentsMap,
		suites:         suitesMap,
	}, nil
}

func (f *UbuntuFilter) Transform(r *http.Request) (*http.Request, bool) {
	err := errOnNonEmptyBody(r)
	if err != nil {
		return nil, false
	}

	if !verifyHeaders(r, f.allowedHeaders) {
		return r, false
	}

	if r.Host != f.host {
		return r, false
	}

	if r.Method != string(verbs.GET) {
		return nil, false
	}

	suffix, ok := strings.CutPrefix(r.URL.Path, f.pathPrefix)
	if !ok {
		return nil, false
	}

	parts := strings.Split(suffix, "/")
	if len(parts) < 2 {
		return nil, false
	}

	switch parts[0] {
	case "dists":
		suite := parts[1]
		_, found := f.suites[suite]
		if !found {
			return nil, false
		}

		if f.matchFixed(parts[2:]) {
			return r, true
		}
	case "pool":
		component := parts[1]
		_, found := f.components[component]
		if !found {
			return nil, false
		}

		if f.matchPackage(parts[2:]) {
			return r, true
		}
	default:
		return nil, false
	}

	return nil, false
}

func (f *UbuntuFilter) MaskSupported() bool {
	return false
}

func (f *UbuntuFilter) matchFixed(parts []string) bool {
	if len(parts) == 1 && parts[0] == "InRelease" {
		return true
	}

	if len(parts) != 5 {
		return false
	}

	component := parts[0]
	_, found := f.components[component]
	if !found {
		return false
	}

	switch parts[1] {
	case "binary-amd64":
	case "i18n":
	case "dep11":
	case "cnf":
	default:
		return false
	}

	if parts[2] != "by-hash" {
		return false
	}

	if parts[3] != "SHA256" {
		return false
	}

	hash := parts[4]
	if !regexSHA256.MatchString(hash) {
		return false
	}

	return true
}

func (f *UbuntuFilter) matchPackage(parts []string) bool {
	if len(parts) != 3 {
		return false
	}

	prefix := parts[0]
	packageName := parts[1]
	filenameEscaped := parts[2]

	if !strings.HasPrefix(packageName, prefix) {
		return false
	}

	if !regexDebianPackageName.MatchString(packageName) {
		return false
	}

	_, found := f.packageTrie.Match([]byte(packageName))
	if !found {
		return false
	}

	filename, err := url.PathUnescape(filenameEscaped)
	if err != nil {
		return false
	}

	if !regexDebianFilename.MatchString(filename) {
		return false
	}

	return true
}
