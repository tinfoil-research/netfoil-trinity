package filters

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/tinfoil-research/netfoil-trinity/internal/trie"
	"github.com/tinfoil-research/netfoil-trinity/internal/verbs"
)

var regexGoPackageName = regexp.MustCompile("^[a-z0-9]+([./][a-z0-9]+)*$")
var regexGoVersion = regexp.MustCompile("^v[0-9]+(\\.[0-9]+)*(-[0-9]{14}-[a-f0-9]{12})?$")
var regexGoTilePath = regexp.MustCompile("^/tile/[0-9]/[0-9](/x[0-9]+)?(/[a-z0-9]+\\.p)?/[0-9]+$")

var regexGoHeaderUserAgent = regexp.MustCompile("^[a-zA-Z0-9/:.+ ()-]+$")
var regexGoHeaderAcceptEncoding = regexp.MustCompile("^gzip$")

type GolangFilter struct {
	trie           trie.Node
	allowedHeaders map[string]*regexp.Regexp
}

func NewGoFilter(allowedPackages []string) (*GolangFilter, error) {
	t := trie.Node{}
	for _, repo := range allowedPackages {
		err := t.Insert(repo, nil)
		if err != nil {
			return nil, err
		}
	}

	allowedHeaders := goAllowedHeaders()
	return &GolangFilter{
		trie:           t,
		allowedHeaders: allowedHeaders,
	}, nil
}

func goAllowedHeaders() map[string]*regexp.Regexp {
	allowedHeaders := make(map[string]*regexp.Regexp)
	allowedHeaders["User-Agent"] = regexGoHeaderUserAgent
	allowedHeaders["Accept-Encoding"] = regexGoHeaderAcceptEncoding

	return allowedHeaders
}

func (f *GolangFilter) Transform(r *http.Request) (*http.Request, bool) {
	err := errOnNonEmptyBody(r)
	if err != nil {
		return nil, false
	}

	if !verifyHeaders(r, f.allowedHeaders) {
		return r, false
	}

	if r.Host == "proxy.golang.org" {
		if r.RequestURI == "/sumdb/sum.golang.org/supported" && r.Method == "GET" {
			return r, true
		}

		parts := strings.Split(r.RequestURI, "/")

		if len(parts) < 4 {
			return nil, false
		}

		if parts[0] != "" {
			return nil, false
		}

		if parts[len(parts)-2] != "@v" {
			return nil, false
		}

		file := parts[len(parts)-1]
		if !(strings.HasSuffix(file, ".zip") ||
			strings.HasSuffix(file, ".mod") ||
			strings.HasSuffix(file, ".info")) {
			return nil, false
		}

		packageName := strings.Join(parts[1:len(parts)-2], "/")
		if !regexGoPackageName.MatchString(packageName) {
			return nil, false
		}

		_, found := f.trie.Match([]byte(packageName))
		if !found {
			return nil, false
		}

		if r.Method == string(verbs.GET) {
			return r, true
		}
	} else if r.Host == "sum.golang.org" {
		if strings.HasPrefix(r.RequestURI, "/tile/") && r.Method == "GET" {
			if !regexGoTilePath.MatchString(r.RequestURI) {
				return nil, false
			}
			return r, true
		}

		lookupPrefix := "/lookup/"
		if after, ok := strings.CutPrefix(r.RequestURI, lookupPrefix); ok {
			parts := strings.Split(after, "@")

			if len(parts) != 2 {
				return nil, false
			}

			packageName := parts[0]
			_, found := f.trie.Match([]byte(packageName))
			if !found {
				return nil, false
			}

			version := parts[1]
			if !regexGoVersion.MatchString(version) {
				return nil, false
			}

			if r.Method == string(verbs.GET) {
				return r, true
			}
		}
	}

	return nil, false
}
