package filters

import (
	"net/http"
	"strings"

	"github.com/tinfoil-research/netfoil-trinity/internal/trie"
	"github.com/tinfoil-research/netfoil-trinity/internal/verbs"
)

type DebianFilter struct {
	packageTrie trie.Node
	fixedTrie   trie.Node
}

func NewDebianFilter(allowedPackages []string) (*DebianFilter, error) {
	packageTrie := trie.Node{}
	for _, repo := range allowedPackages {
		err := packageTrie.Insert(repo, nil)
		if err != nil {
			return nil, err
		}
	}

	fixedList := []string{
		"InRelease",
		"main/source/Sources",
		"main/source/Sources.xz",
		"main/source/by-hash/SHA256/*",
		"non-free-firmware/source/by-hash/SHA256/*",

		"main/binary-amd64/Packages",
		"main/binary-amd64/Packages.xz",
		"main/binary-amd64/by-hash/SHA256/*",
		"non-free-firmware/binary-amd64/by-hash/SHA256/*",

		"main/i18n/Translation-en",
		"main/i18n/Translation-en.xz",
		"non-free-firmware/i18n/Translation-en",
		"non-free-firmware/i18n/Translation-en.xz",
		"main/i18n/by-hash/SHA256/*",
		"non-free-firmware/i18n/by-hash/SHA256/*",

		"main/dep11/Components-amd64.yml",
		"main/dep11/Components-amd64.yml.gz",
		"main/dep11/icons-48x48.tar.gz",
		"main/dep11/icons-64x64.tar.gz",
		"non-free-firmware/dep11/Components-amd64.yml",
		"non-free-firmware/dep11/Components-amd64.yml.gz",
		"non-free-firmware/dep11/icons-48x48.tar.gz",
		"non-free-firmware/dep11/icons-64x64.tar.gz",
		"main/dep11/by-hash/SHA256/*",
		"non-free-firmware/dep11/by-hash/SHA256/*",
	}

	fixedTrie := trie.Node{}
	for _, fixed := range fixedList {
		err := fixedTrie.Insert(fixed, nil)
		if err != nil {
			return nil, err
		}
	}

	return &DebianFilter{
		packageTrie: packageTrie,
		fixedTrie:   fixedTrie,
	}, nil
}

func (f *DebianFilter) Transform(r *http.Request) (*http.Request, bool) {
	if r.Host == "security.debian.org" {
		if r.Method != string(verbs.GET) {
			return nil, false
		}

		distTrixieSecurityPrefix := "/debian-security/dists/trixie-security/"
		if f.matchFixed(r, distTrixieSecurityPrefix) {
			return r, true
		}

		poolPrefix := "/debian-security/pool/updates/main/"
		if f.matchPackage(r, poolPrefix) {
			return r, true
		}
	} else if r.Host == "deb.debian.org" {
		if r.Method != string(verbs.GET) {
			return nil, false
		}

		distTrixiePrefix := "/debian/dists/trixie/"
		if f.matchFixed(r, distTrixiePrefix) {
			return r, true
		}

		distTrixieUpdatesPrefix := "/debian/dists/trixie-updates/"
		if f.matchFixed(r, distTrixieUpdatesPrefix) {
			return r, true
		}

		poolPrefix := "/debian/pool/main/"
		if f.matchPackage(r, poolPrefix) {
			return r, true
		}
	}

	return nil, false
}

func (f *DebianFilter) matchFixed(r *http.Request, distPrefix string) bool {
	if after, ok := strings.CutPrefix(r.RequestURI, distPrefix); ok {
		_, match := f.fixedTrie.Match([]byte(after))
		if match {
			return true
		}
	}

	return false
}

func (f *DebianFilter) matchPackage(r *http.Request, poolPrefix string) bool {
	if after, ok := strings.CutPrefix(r.RequestURI, poolPrefix); ok {
		parts := strings.Split(after, "/")

		if len(parts) != 3 {
			return false
		}

		leadingCharacter := parts[0]
		packageName := parts[1]

		if string(packageName[0]) != leadingCharacter {
			return false
		}

		_, found := f.packageTrie.Match([]byte(packageName))
		if !found {
			return false
		}

		file := parts[2]
		if !strings.HasSuffix(file, ".deb") {
			return false
		}

		return true
	}

	return false
}
