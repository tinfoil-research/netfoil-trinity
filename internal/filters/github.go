package filters

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/tinfoil-research/netfoil-trinity/internal/trie"
	"github.com/tinfoil-research/netfoil-trinity/internal/verbs"
)

var regexGitHubOrg = regexp.MustCompile("^[a-zA-Z0-9]+(-[a-zA-Z0-9]+)*$")
var regexGitHubRepo = regexp.MustCompile("^[a-zA-Z0-9]+(-[a-zA-Z0-9]+)*$")

var regexGitHubHeaderPragma = regexp.MustCompile("^no-cache$")
var regexGitHubHeaderGitProtocol = regexp.MustCompile("^version=2$")
var regexGitHubHeaderUserAgent = regexp.MustCompile("^[a-z0-9./]+$")
var regexGitHubHeaderAccept = regexp.MustCompile("^*/*$")
var regexGitHubHeaderAcceptEncoding = regexp.MustCompile("^[a-z, ]+$")
var regexGitHubHeaderAcceptLanguage = regexp.MustCompile("^[a-zA-Z0-9;=*., -]+$")
var regexGitHubHeaderContentType = regexp.MustCompile("^application/x-git-upload-pack-request$")
var regexGitHubHeaderContentLength = regexp.MustCompile("^[0-9]+$")

type GitHubFilter struct {
	trie           trie.Node
	allowedHeaders map[string]*regexp.Regexp
}

func NewGitHubFilter(allowedRepos []string) (*GitHubFilter, error) {
	t := trie.Node{}
	for _, repo := range allowedRepos {
		err := t.Insert(repo, nil)
		if err != nil {
			return nil, err
		}
	}

	allowedHeaders := gitHubAllowedHeaders()
	return &GitHubFilter{
		trie:           t,
		allowedHeaders: allowedHeaders,
	}, nil
}

func gitHubAllowedHeaders() map[string]*regexp.Regexp {
	allowedHeaders := make(map[string]*regexp.Regexp)
	allowedHeaders["Pragma"] = regexGitHubHeaderPragma
	allowedHeaders["Git-Protocol"] = regexGitHubHeaderGitProtocol
	allowedHeaders["User-Agent"] = regexGitHubHeaderUserAgent
	allowedHeaders["Accept"] = regexGitHubHeaderAccept
	allowedHeaders["Accept-Encoding"] = regexGitHubHeaderAcceptEncoding
	allowedHeaders["Accept-Language"] = regexGitHubHeaderAcceptLanguage
	allowedHeaders["Content-Type"] = regexGitHubHeaderContentType
	allowedHeaders["Content-Length"] = regexGitHubHeaderContentLength

	return allowedHeaders
}

func (f *GitHubFilter) Transform(r *http.Request) (*http.Request, bool) {
	if !verifyHeaders(r, f.allowedHeaders) {
		return r, false
	}

	parts := strings.Split(r.RequestURI, "/")

	if len(parts) < 3 {
		return nil, false
	}

	if parts[0] != "" {
		return nil, false
	}

	org := parts[1]
	if !regexGitHubOrg.MatchString(org) {
		return nil, false
	}

	if strings.HasPrefix(parts[2], ".git") {
		return nil, false
	}
	repo := strings.TrimSuffix(parts[2], ".git")

	if !regexGitHubRepo.MatchString(repo) {
		return nil, false
	}

	slug := org + "/" + repo

	_, found := f.trie.Match([]byte(slug))
	if !found {
		return nil, false
	}

	suffix := strings.Join(parts[3:], "/")

	if suffix == "info/refs?service=git-upload-pack" && r.Method == string(verbs.GET) {
		err := errOnNonEmptyBody(r)
		if err != nil {
			return nil, false
		}

		return r, true
	}

	if suffix == "git-upload-pack" && r.Method == string(verbs.POST) {
		return r, true
	}

	return r, false
}
