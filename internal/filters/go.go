package filters

import (
	"net/http"
	"strings"

	"github.com/tinfoil-research/netfoil-trinity/internal/trie"
	"github.com/tinfoil-research/netfoil-trinity/internal/verbs"
)

type GolangFilter struct {
	trie trie.Node
}

func NewGoFilter(allowedPackages []string) (*GolangFilter, error) {
	t := trie.Node{}
	for _, repo := range allowedPackages {
		err := t.Insert(repo, nil)
		if err != nil {
			return nil, err
		}
	}

	return &GolangFilter{trie: t}, nil
}

func (f *GolangFilter) Transform(r *http.Request) (*http.Request, bool) {
	err := errOnNonEmptyBody(r)
	if err != nil {
		return nil, false
	}

	if r.Host == "proxy.golang.org" {
		if r.RequestURI == "/sumdb/sum.golang.org/supported" && r.Method == "GET" {
			return r, true
		}

		parts := strings.Split(r.RequestURI, "/")

		if len(parts) < 4 {
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
		_, found := f.trie.Match([]byte(packageName))
		if !found {
			return nil, false
		}

		if r.Method == string(verbs.GET) {
			return r, true
		}
	} else if r.Host == "sum.golang.org" {
		if strings.HasPrefix(r.RequestURI, "/tile/") && r.Method == "GET" {
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

			if r.Method == string(verbs.GET) {
				return r, true
			}
		}
	}

	return nil, false
}
