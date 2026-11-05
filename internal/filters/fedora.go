package filters

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/tinfoil-research/netfoil-trinity/internal/trie"
	"github.com/tinfoil-research/netfoil-trinity/internal/verbs"
)

var regexFedoraPackageName = regexp.MustCompile(`^[a-zA-Z0-9+_-]+(\.[a-zA-Z0-9+_-]+)*$`)
var regexFedoraVersion = regexp.MustCompile(`^([0-9]:)?[0-9a-z]+(\.[0-9a-z]+){0,2}([+^_][0-9a-z]+(\.[0-9a-z]+){0,2})?-[0-9a-z]+(\.[0-9a-z]+){0,2}$`)

var regexRepodata = regexp.MustCompile(`[0-9a-f]{64}-(updateinfo\.xml\.zck|comps-Everything\.x86_64\.xml\.zst|primary\.xml\.zck)`)

type fedoraArtifact struct {
	packageName *string
}

type FedoraFilter struct {
	host           string
	pathPrefix     string
	packageTrie    trie.Node
	fixedTrie      trie.Node
	allowedHeaders map[string]*regexp.Regexp
	maskRequest    bool
	fedoraVersion  int
	architecture   string
}

func NewFedoraFilter(allowedPackages []string, repoPrefix *url.URL, maskRequest bool) (*FedoraFilter, error) {
	packageTrie := trie.Node{}
	for _, repo := range allowedPackages {
		err := packageTrie.Insert(repo, nil)
		if err != nil {
			return nil, err
		}
	}

	return &FedoraFilter{
		host:          repoPrefix.Host,
		pathPrefix:    repoPrefix.Path,
		packageTrie:   packageTrie,
		maskRequest:   maskRequest,
		fedoraVersion: 44,
		architecture:  "x86_64",
	}, nil
}

func (f *FedoraFilter) Transform(r *http.Request) (*http.Request, bool) {
	artifact, allow := f.allowRequest(r)
	if !allow || artifact == nil {
		return nil, false
	}

	if f.maskRequest {
		newRequest := &http.Request{}
		newRequest.Host = r.Host
		newRequest.URL = r.URL

		newRequest.Method = string(verbs.GET)
		newRequest.Header = make(map[string][]string)

		newRequest.Header.Set("User-Agent", fedoraUserAgent(f.fedoraVersion, f.architecture))
		newRequest.Header.Set("Accept", "*/*")

		if artifact.packageName == nil {
			newRequest.Header.Set("Cache-Control", "no-cache")
			newRequest.Header.Set("Pragma", "no-cache")

			rangeValue := r.Header.Get("Range")
			if rangeValue != "" {
				newRequest.Header.Set("Range", rangeValue)
			}
		}
	}

	return r, true
}

func (f *FedoraFilter) MaskSupported() bool {
	return true
}

func (f *FedoraFilter) allowRequest(r *http.Request) (*fedoraArtifact, bool) {
	if r.Method != string(verbs.GET) {
		return nil, false
	}

	err := errOnNonEmptyBody(r)
	if err != nil {
		return nil, false
	}

	if r.Host != f.host {
		return nil, false
	}

	artifact, allow := f.verifyPath(r)
	if !allow {
		return nil, false
	}

	if !verifyFedoraHeaders(r, f.fedoraVersion, f.architecture, artifact) {
		return nil, false
	}

	return artifact, true
}

func (f *FedoraFilter) verifyPath(r *http.Request) (*fedoraArtifact, bool) {
	after, ok := strings.CutPrefix(r.RequestURI, f.pathPrefix)
	if !ok {
		return nil, false
	}

	parts := strings.Split(after, "/")

	if len(parts) < 6 || len(parts) > 8 {
		return nil, false
	}

	releasesOrUpdates := parts[0]
	if !(releasesOrUpdates == "releases" || releasesOrUpdates == "updates") {
		return nil, false
	}

	version, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, false
	}

	if version != f.fedoraVersion {
		return nil, false
	}

	if parts[2] != "Everything" {
		return nil, false
	}

	if parts[3] != f.architecture {
		return nil, false
	}

	repomdxml := "repomd.xml"
	var packageName *string = nil
	allow := false
	switch parts[4] {
	case "repodata":
		if parts[5] != repomdxml {
			if !regexRepodata.MatchString(parts[5]) {
				return nil, false
			}
		}
	case "os":
		switch parts[5] {
		case "Packages":
			if len(parts) != 8 {
				return nil, false
			}

			packageName, allow = f.verifyPackage(parts[6:])
			if !allow {
				return nil, false
			}
		case "repodata":
			if len(parts) != 7 {
				return nil, false
			}
			if parts[6] != repomdxml {
				if !regexRepodata.MatchString(parts[6]) {
					return nil, false
				}
			}
		}
	case "Packages":
		if len(parts) != 7 {
			return nil, false
		}
		packageName, allow = f.verifyPackage(parts[5:])
		if !allow {
			return nil, false
		}
	default:
		return nil, false
	}

	return &fedoraArtifact{
		packageName: packageName,
	}, true
}

func (f *FedoraFilter) verifyPackage(parts []string) (*string, bool) {
	if len(parts) != 2 {
		return nil, false
	}

	leadingCharacter := parts[0]
	filename := parts[1]

	if !strings.HasPrefix(strings.ToLower(string(filename[0])), leadingCharacter) {
		return nil, false
	}

	fileSuffix := fmt.Sprintf(".fc%d.%s.rpm", f.fedoraVersion, f.architecture)
	packageNameAndVersion, ok := strings.CutSuffix(filename, fileSuffix)
	if !ok {
		fileSuffix := fmt.Sprintf(".fc%d.%s.rpm", f.fedoraVersion, "noarch")
		packageNameAndVersion, ok = strings.CutSuffix(filename, fileSuffix)
		if !ok {
			return nil, false
		}
	}

	packageNameAndVersionParts := strings.Split(packageNameAndVersion, "-")
	if len(packageNameAndVersionParts) < 3 {
		return nil, false
	}

	packageNameRaw := strings.Join(packageNameAndVersionParts[0:len(packageNameAndVersionParts)-2], "-")
	packageName, err := url.PathUnescape(packageNameRaw)
	if err != nil {
		return nil, false
	}

	if !regexFedoraPackageName.MatchString(packageName) {
		return nil, false
	}

	_, found := f.packageTrie.Match([]byte(packageName))
	if !found {
		return nil, false
	}

	version := strings.Join(packageNameAndVersionParts[len(packageNameAndVersionParts)-2:], "-")
	if !regexFedoraVersion.MatchString(version) {
		return nil, false
	}

	return &packageName, true
}

func verifyFedoraHeaders(r *http.Request, fedoraVersion int, architecture string, artifact *fedoraArtifact) bool {
	for k, v := range r.Header {
		if len(v) != 1 {
			return false
		}

		switch k {
		case "Cache-Control":
			if artifact.packageName != nil {
				return false
			}

			if v[0] != "no-cache" {
				return false
			}
		case "Pragma":
			if artifact.packageName != nil {
				return false
			}

			if v[0] != "no-cache" {
				return false
			}
		case "Accept":
			if v[0] != "*/*" {
				return false
			}
		case "User-Agent":
			if v[0] != fedoraUserAgent(fedoraVersion, architecture) {
				return false
			}
		case "Range":
			if !regexHeaderRange.MatchString(v[0]) {
				return false
			}
		}
	}

	return true
}

func fedoraUserAgent(version int, architecture string) string {
	return fmt.Sprintf("libdnf (Fedora Linux %d; server; Linux.%s)", version, architecture)
}
