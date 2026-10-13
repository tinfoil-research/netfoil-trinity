package filters

import (
	"net/http"
	"strings"

	"github.com/tinfoil-research/netfoil-trinity/internal/trie"
	"github.com/tinfoil-research/netfoil-trinity/internal/verbs"
)

type GitHubFilter struct {
	trie trie.Node
}

func NewGitHubFilter(allowedRepos []string) (*GitHubFilter, error) {
	t := trie.Node{}
	for _, repo := range allowedRepos {
		err := t.Insert(repo, nil)
		if err != nil {
			return nil, err
		}
	}

	return &GitHubFilter{trie: t}, nil
}

func (f *GitHubFilter) Transform(r *http.Request) (*http.Request, bool) {
	parts := strings.Split(r.RequestURI, "/")

	if len(parts) < 3 {
		return nil, false
	}

	if parts[0] != "" {
		return nil, false
	}

	org := parts[1]

	if strings.HasPrefix(parts[2], ".git") {
		return nil, false
	}
	repo := strings.TrimSuffix(parts[2], ".git")

	slug := org + "/" + repo

	_, found := f.trie.Match([]byte(slug))
	if !found {
		return nil, false
	}

	suffix := strings.Join(parts[3:], "/")

	if suffix == "info/refs?service=git-upload-pack" && r.Method == string(verbs.GET) {
		return r, true
	}

	if suffix == "git-upload-pack" && r.Method == string(verbs.POST) {
		return r, true
	}

	return r, false
}
