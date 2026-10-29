package filters

import (
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/tinfoil-research/netfoil-trinity/internal/trie"
	"github.com/tinfoil-research/netfoil-trinity/internal/verbs"
)

var regexFedoraPath = regexp.MustCompile("^(/[a-zA-Z0-9-_]+)*(\\.xml|\\.xml\\.zck|\\.x86_64.xml.zst)?$")

// FIXME proper parsing
var regexFedoraPackageName = regexp.MustCompile("^[a-zA-Z0-9+_-]+(\\.[a-zA-Z0-9+_-]+)*$")
var regexFedoraPart2 = regexp.MustCompile("^[0-9a-z+^]+(\\.[0-9a-z+^]+)*")
var regexFedoraPart3 = regexp.MustCompile("^[0-9a-z]+\\.fc44\\.(x86_64|noarch)\\.rpm|$")

var regexFedoraHeaderCacheControl = regexp.MustCompile("^no-cache$")
var regexFedoraHeaderPragma = regexp.MustCompile("^no-cache$")
var regexFedoraHeaderUserAgent = regexp.MustCompile("^[a-zA-Z0-9.; ()_]+$")
var regexFedoraHeaderAccept = regexp.MustCompile("^\\*/\\*$")

type FedoraFilter struct {
	host           string
	pathPrefix     string
	packageTrie    trie.Node
	fixedTrie      trie.Node
	allowedHeaders map[string]*regexp.Regexp
}

func NewFedoraFilter(allowedPackages []string, repoPrefix *url.URL) (*FedoraFilter, error) {
	packageTrie := trie.Node{}
	for _, repo := range allowedPackages {
		err := packageTrie.Insert(repo, nil)
		if err != nil {
			return nil, err
		}
	}

	fixedList := []string{
		"releases/44/Everything/x86_64/repodata/repomd.xml",
		"releases/44/Everything/x86_64/repodata/*",
		"releases/44/Everything/x86_64/os/repodata/repomd.xml",
		"releases/44/Everything/x86_64/os/repodata/*",

		"updates/44/Everything/x86_64/repodata/repomd.xml",
		"updates/44/Everything/x86_64/repodata/*",
		"updates/44/Everything/x86_64/os/repodata/repomd.xml",
		"updates/44/Everything/x86_64/os/repodata/*",
	}

	for i, l := range fixedList {
		fixedList[i] = filepath.Join(repoPrefix.Path, l)
	}

	fixedTrie := trie.Node{}
	for _, fixed := range fixedList {
		err := fixedTrie.Insert(fixed, nil)
		if err != nil {
			return nil, err
		}
	}

	allowedHeaders := fedoraAllowedHeaders()
	return &FedoraFilter{
		host:           repoPrefix.Host,
		pathPrefix:     repoPrefix.Path,
		packageTrie:    packageTrie,
		fixedTrie:      fixedTrie,
		allowedHeaders: allowedHeaders,
	}, nil
}

func fedoraAllowedHeaders() map[string]*regexp.Regexp {
	allowedHeaders := make(map[string]*regexp.Regexp)
	allowedHeaders["Cache-Control"] = regexFedoraHeaderCacheControl
	allowedHeaders["Pragma"] = regexFedoraHeaderPragma
	allowedHeaders["User-Agent"] = regexFedoraHeaderUserAgent
	allowedHeaders["Accept"] = regexFedoraHeaderAccept
	allowedHeaders["Range"] = regexHeaderRange
	return allowedHeaders
}

func (f *FedoraFilter) Transform(r *http.Request) (*http.Request, bool) {
	err := errOnNonEmptyBody(r)
	if err != nil {
		return nil, false
	}

	if !verifyHeaders(r, f.allowedHeaders) {
		return r, false
	}

	if r.Host == f.host {
		if r.Method != string(verbs.GET) {
			return nil, false
		}

		if f.matchFixed(r, "") {
			return r, true
		}

		releasesPrefix := filepath.Join(f.pathPrefix, "releases/44/Everything/x86_64/os/Packages/") + "/"
		if f.matchPackage(r, releasesPrefix) {
			return r, true
		}

		updatesPrefix := filepath.Join(f.pathPrefix, "updates/44/Everything/x86_64/Packages/") + "/"
		if f.matchPackage(r, updatesPrefix) {
			return r, true
		}
	}

	return nil, false
}

func (f *FedoraFilter) matchFixed(r *http.Request, distPrefix string) bool {
	if after, ok := strings.CutPrefix(r.RequestURI, distPrefix); ok {
		if !regexFedoraPath.MatchString(after) {
			return false
		}

		_, match := f.fixedTrie.Match([]byte(after))
		if match {
			return true
		}
	}

	return false
}

func (f *FedoraFilter) matchPackage(r *http.Request, poolPrefix string) bool {
	if after, ok := strings.CutPrefix(r.RequestURI, poolPrefix); ok {
		parts := strings.Split(after, "/")

		if len(parts) != 2 {
			return false
		}

		leadingCharacter := parts[0]
		file := parts[1]

		if !strings.HasPrefix(strings.ToLower(string(file[0])), leadingCharacter) {
			return false
		}

		filenameParts := strings.Split(file, "-")
		if len(filenameParts) < 3 {
			return false
		}

		packageNameRaw := strings.Join(filenameParts[0:len(filenameParts)-2], "-")
		packageName, err := url.QueryUnescape(packageNameRaw)
		if err != nil {
			return false
		}

		part2 := filenameParts[len(filenameParts)-2]
		part3 := filenameParts[len(filenameParts)-1]

		if !regexFedoraPackageName.MatchString(packageName) {
			return false
		}

		if !regexFedoraPart2.MatchString(part2) {
			return false
		}

		if !regexFedoraPart3.MatchString(part3) {
			return false
		}

		_, found := f.packageTrie.Match([]byte(packageName))
		if !found {
			return false
		}

		return true
	}

	return false
}
