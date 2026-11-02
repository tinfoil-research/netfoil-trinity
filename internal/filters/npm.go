package filters

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/tinfoil-research/netfoil-trinity/internal/trie"
	"github.com/tinfoil-research/netfoil-trinity/internal/verbs"
)

var regexNPMScope = regexp.MustCompile(`^@[a-z0-9-]+$`)
var regexNPMPackageName = regexp.MustCompile(`^[a-z0-9-_]+$`)
var regexNPMFilename = regexp.MustCompile(`^[a-z0-9-_]+[0-9]+(\.[0-9]+)*\.tgz$`)

var regexNPMHeaderPacoteVersion = regexp.MustCompile(`^[0-9]+(\.[0-9]+){0,2}$`)
var regexNPMHeaderPacoteReqType = regexp.MustCompile(`^(packument|tarball)$`)
var regexNPMHeaderPacotePkgId = regexp.MustCompile(`^(registry:(@[a-z0-9-]+/)?[a-z0-9-_]+|remote:(@[a-z0-9-]+/)?[a-z0-9-_]+@https://registry\.npmjs\.org/(@[a-z0-9-]+/)?[a-z0-9-_]+/-/[a-z0-9-_]+-[0-9]+(\.[0-9]+)*\.tgz)$`)
var regexNPMHeaderPacoteIntegrity = regexp.MustCompile(`^sha512-[a-zA-Z0-9/+]+(==)?$`)
var regexNPMHeaderConnection = regexp.MustCompile(`^keep-alive$`)
var regexNPMHeaderAccept = regexp.MustCompile(`^(application/vnd\.npm\.install-v1\+json; q=1\.0|application/json; q=0\.8|\*/\*)$`)
var regexNPMHeaderAcceptEncoding = regexp.MustCompile(`^(gzip|deflate)$`)
var regexNPMHeaderAuthType = regexp.MustCompile(`^web$`)
var regexNPMHeaderCommand = regexp.MustCompile(`^install$`)
var regexNPMHeaderUserAgent = regexp.MustCompile(`^[a-z/0-9. ]+$`)
var regexNPMHeaderIfNoneMatch = regexp.MustCompile(`^[a-zA-Z0-9/"]+$`)
var regexNPMHeaderIfModifiedSince = regexp.MustCompile(`^[A-Za-z]{3}, [0-9]{2} [A-Za-z]{3} [0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2} [A-Z]{3}?$`)

type NPMFilter struct {
	trie           trie.Node
	allowedHeaders map[string]*regexp.Regexp
}

func NewNPMFilter(allowedPackages []string) (*NPMFilter, error) {
	t := trie.Node{}
	for _, repo := range allowedPackages {
		err := t.Insert(repo, nil)
		if err != nil {
			return nil, err
		}
	}

	allowedHeaders := npmAllowedHeaders()
	return &NPMFilter{
		trie:           t,
		allowedHeaders: allowedHeaders,
	}, nil
}

func npmAllowedHeaders() map[string]*regexp.Regexp {
	allowedHeaders := make(map[string]*regexp.Regexp)
	allowedHeaders["Pacote-Version"] = regexNPMHeaderPacoteVersion
	allowedHeaders["Pacote-Req-Type"] = regexNPMHeaderPacoteReqType
	allowedHeaders["Pacote-Pkg-Id"] = regexNPMHeaderPacotePkgId
	allowedHeaders["Pacote-Integrity"] = regexNPMHeaderPacoteIntegrity

	allowedHeaders["Connection"] = regexNPMHeaderConnection
	allowedHeaders["Accept"] = regexNPMHeaderAccept
	allowedHeaders["Accept-Encoding"] = regexNPMHeaderAcceptEncoding
	allowedHeaders["User-Agent"] = regexNPMHeaderUserAgent

	allowedHeaders["Npm-Auth-Type"] = regexNPMHeaderAuthType
	allowedHeaders["Npm-Command"] = regexNPMHeaderCommand

	allowedHeaders["If-None-Match"] = regexNPMHeaderIfNoneMatch
	allowedHeaders["If-Modified-Since"] = regexNPMHeaderIfModifiedSince

	return allowedHeaders
}

func (f *NPMFilter) Transform(r *http.Request) (*http.Request, bool) {
	if r.Method != string(verbs.GET) {
		return nil, false
	}

	err := errOnNonEmptyBody(r)
	if err != nil {
		return nil, false
	}

	if !verifyNPMHeaders(r, f.allowedHeaders) {
		return nil, false
	}

	parts := strings.Split(r.RequestURI, "/")

	if len(parts) < 2 {
		return nil, false
	}

	if parts[0] != "" {
		return nil, false
	}

	if len(parts) == 2 {
		id, err := url.PathUnescape(parts[1])
		if err != nil {
			return nil, false
		}

		idParts := strings.Split(id, "/")
		if len(idParts) == 0 || len(idParts) > 2 {
			return nil, false
		}

		packageName := idParts[0]

		if len(idParts) == 2 {
			scope := idParts[0]
			packageName = idParts[1]

			if !regexNPMScope.MatchString(scope) {
				return nil, false
			}
		}

		if !regexNPMPackageName.MatchString(packageName) {
			return nil, false
		}

		_, found := f.trie.Match([]byte(id))
		if !found {
			return nil, false
		}

		return r, true
	} else if len(parts) == 4 {
		packageName := parts[1]
		if !regexNPMPackageName.MatchString(packageName) {
			return nil, false
		}

		if parts[2] != "-" {
			return nil, false
		}

		filename := parts[3]
		if !regexNPMFilename.MatchString(filename) {
			return nil, false
		}

		if !strings.HasPrefix(filename, packageName) {
			return nil, false
		}

		_, found := f.trie.Match([]byte(packageName))
		if !found {
			return nil, false
		}

		return r, true
	} else if len(parts) == 5 {
		scope := parts[1]
		if !regexNPMScope.MatchString(scope) {
			return nil, false
		}

		packageName := parts[2]
		if !regexNPMPackageName.MatchString(packageName) {
			return nil, false
		}

		if parts[3] != "-" {
			return nil, false
		}

		filename := parts[4]
		if !regexNPMFilename.MatchString(filename) {
			return nil, false
		}

		if !strings.HasPrefix(filename, packageName) {
			return nil, false
		}

		id := scope + "/" + packageName
		_, found := f.trie.Match([]byte(id))
		if !found {
			return nil, false
		}

		return r, true
	}

	return nil, false
}

func verifyNPMHeaders(r *http.Request, allowedHeaders map[string]*regexp.Regexp) bool {
	for k, v := range r.Header {
		regex, found := allowedHeaders[k]
		if !found {
			return false
		}

		if len(v) != 1 {
			return false
		}

		switch k {
		case "Accept":
			parts := strings.Split(v[0], ", ")
			for _, p := range parts {
				if !regex.MatchString(p) {
					return false
				}
			}
		case "Accept-Encoding":
			parts := strings.Split(v[0], ",")
			for _, p := range parts {
				if !regex.MatchString(p) {
					return false
				}
			}
		default:
			if !regex.MatchString(v[0]) {
				return false
			}
		}
	}

	return true
}
