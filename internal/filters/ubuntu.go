package filters

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/tinfoil-research/netfoil-trinity/internal/trie"
	"github.com/tinfoil-research/netfoil-trinity/internal/verbs"
)

var regexUbuntuFilename = regexp.MustCompile("^[a-z0-9_-]+(\\.[a-z0-9_-]+)*\\.deb$")

type UbuntuFilter struct {
	packageTrie trie.Node
	fixedTrie   trie.Node
}

func NewUbuntuFilter(allowedPackages []string) (*UbuntuFilter, error) {
	packageTrie := trie.Node{}
	for _, repo := range allowedPackages {
		err := packageTrie.Insert(repo, nil)
		if err != nil {
			return nil, err
		}
	}

	fixedList := []string{
		"InRelease",
	}

	fixedTrie := trie.Node{}
	for _, fixed := range fixedList {
		err := fixedTrie.Insert(fixed, nil)
		if err != nil {
			return nil, err
		}
	}

	return &UbuntuFilter{
		packageTrie: packageTrie,
		fixedTrie:   fixedTrie,
	}, nil
}

func (f *UbuntuFilter) Transform(r *http.Request) (*http.Request, bool) {
	if r.Host == "security.ubuntu.com" {
		if r.Method != string(verbs.GET) {
			return nil, false
		}

		distTrixieSecurityPrefix := "/ubuntu/dists/resolute-security/"
		if f.matchFixed(r, distTrixieSecurityPrefix) {
			return r, true
		}

		poolPrefix := "/ubuntu/pool/main/"
		if f.matchPackage(r, poolPrefix) {
			return r, true
		}
	} else if r.Host == "archive.ubuntu.com" {
		if r.Method != string(verbs.GET) {
			return nil, false
		}

		distTrixiePrefix := "/ubuntu/dists/resolute/"
		if f.matchFixed(r, distTrixiePrefix) {
			return r, true
		}

		distResoluteUpdatesPrefix := "/ubuntu/dists/resolute-updates/"
		if f.matchFixed(r, distResoluteUpdatesPrefix) {
			return r, true
		}

		distResoluteBackportsPrefix := "/ubuntu/dists/resolute-backports/"
		if f.matchFixed(r, distResoluteBackportsPrefix) {
			return r, true
		}

		poolPrefix := "/ubuntu/pool/main/"
		if f.matchPackage(r, poolPrefix) {
			return r, true
		}
	}

	return nil, false
}

func (f *UbuntuFilter) matchFixed(r *http.Request, distPrefix string) bool {
	if after, ok := strings.CutPrefix(r.RequestURI, distPrefix); ok {
		if !regexCharacters.MatchString(after) {
			return false
		}

		_, match := f.fixedTrie.Match([]byte(after))
		if match {
			return true
		}
	}

	return false
}

func (f *UbuntuFilter) matchPackage(r *http.Request, poolPrefix string) bool {
	if after, ok := strings.CutPrefix(r.RequestURI, poolPrefix); ok {
		parts := strings.Split(after, "/")

		if len(parts) != 3 {
			return false
		}

		prefix := parts[0]
		packageName := parts[1]
		file := parts[2]

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

		if !regexUbuntuFilename.MatchString(file) {
			return false
		}

		return true
	}

	return false
}
