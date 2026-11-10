package filters

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/tinfoil-research/netfoil-trinity/internal/trie"
	"github.com/tinfoil-research/netfoil-trinity/internal/verbs"
)

var regexGitHubOrg = regexp.MustCompile(`^[a-zA-Z0-9]+(-[a-zA-Z0-9]+)*$`)
var regexGitHubRepo = regexp.MustCompile(`^[a-zA-Z0-9]+(-[a-zA-Z0-9]+)*$`)

var regexGitHubHeaderPragma = regexp.MustCompile(`^no-cache$`)
var regexGitHubHeaderGitProtocol = regexp.MustCompile(`^version=2$`)
var regexGitHubHeaderUserAgent = regexp.MustCompile(`^[a-z0-9./]+$`)
var regexGitHubHeaderAccept = regexp.MustCompile(`^(\*/\*|application/x-git-upload-pack-result|application/x-git-receive-pack-result)$`)
var regexGitHubHeaderAcceptEncoding = regexp.MustCompile(`^[a-z, ]+$`)
var regexGitHubHeaderAcceptLanguage = regexp.MustCompile(`^[a-zA-Z0-9;=*., -]+$`)
var regexGitHubHeaderContentType = regexp.MustCompile(`^(application/x-git-upload-pack-request|application/x-git-receive-pack-request)$`)
var regexGitHubHeaderContentLength = regexp.MustCompile(`^[0-9]+$`)
var regexGitHubHeaderContentEncoding = regexp.MustCompile(`^gzip$`)
var regexGitHubHeaderAuthorization = regexp.MustCompile(`^Basic [a-zA-Z0-9]+$`)

type GitHubFilter struct {
	readTrie                 trie.Node
	readWriteTrie            trie.Node
	allowedHeaders           map[string]*regexp.Regexp
	authorizationHeaderValue *string
}

func NewGitHubFilter(allowedReadRepos []string, allowedReadWriteRepos []string, token *string) (*GitHubFilter, error) {
	readTrie := trie.Node{}
	for _, repo := range allowedReadRepos {
		err := readTrie.Insert(repo, nil)
		if err != nil {
			return nil, err
		}
	}

	readWriteTrie := trie.Node{}
	for _, repo := range allowedReadWriteRepos {
		err := readWriteTrie.Insert(repo, nil)
		if err != nil {
			return nil, err
		}
	}

	var authorizationHeaderValue *string = nil
	if token != nil {
		encodedToken := encodeToken(*token)
		authorizationHeaderValue = &encodedToken
	}

	allowedHeaders := gitHubAllowedHeaders(token != nil)
	return &GitHubFilter{
		readTrie:                 readTrie,
		readWriteTrie:            readWriteTrie,
		allowedHeaders:           allowedHeaders,
		authorizationHeaderValue: authorizationHeaderValue,
	}, nil
}

func gitHubAllowedHeaders(allowAuthorizationHeader bool) map[string]*regexp.Regexp {
	allowedHeaders := make(map[string]*regexp.Regexp)
	allowedHeaders["Pragma"] = regexGitHubHeaderPragma
	allowedHeaders["Git-Protocol"] = regexGitHubHeaderGitProtocol
	allowedHeaders["User-Agent"] = regexGitHubHeaderUserAgent
	allowedHeaders["Accept"] = regexGitHubHeaderAccept
	allowedHeaders["Accept-Encoding"] = regexGitHubHeaderAcceptEncoding
	allowedHeaders["Accept-Language"] = regexGitHubHeaderAcceptLanguage
	allowedHeaders["Content-Type"] = regexGitHubHeaderContentType
	allowedHeaders["Content-Length"] = regexGitHubHeaderContentLength
	allowedHeaders["Content-Encoding"] = regexGitHubHeaderContentEncoding

	if allowAuthorizationHeader {
		allowedHeaders["Authorization"] = regexGitHubHeaderAuthorization
	}

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

	repo := strings.TrimSuffix(parts[2], ".git")
	if !regexGitHubRepo.MatchString(repo) {
		return nil, false
	}

	slug := org + "/" + repo

	suffix := strings.Join(parts[3:], "/")

	if suffix == "info/refs?service=git-upload-pack" && r.Method == string(verbs.GET) {
		err := errOnNonEmptyBody(r)
		if err != nil {
			return nil, false
		}

		_, found := f.readTrie.Match([]byte(slug))
		if !found {
			_, found := f.readWriteTrie.Match([]byte(slug))
			if !found {
				return nil, false
			}
		}

		if f.authorizationHeaderValue != nil {
			r.Header.Set("Authorization", *f.authorizationHeaderValue)
		}

		return r, true
	}

	if suffix == "git-upload-pack" && r.Method == string(verbs.POST) {
		if f.authorizationHeaderValue != nil {
			r.Header.Set("Authorization", *f.authorizationHeaderValue)
		}

		_, found := f.readTrie.Match([]byte(slug))
		if !found {
			_, found := f.readWriteTrie.Match([]byte(slug))
			if !found {
				return nil, false
			}
		}

		return r, true
	}

	if suffix == "info/refs?service=git-receive-pack" && r.Method == string(verbs.GET) {
		err := errOnNonEmptyBody(r)
		if err != nil {
			return nil, false
		}

		_, found := f.readWriteTrie.Match([]byte(slug))
		if !found {
			return nil, false
		}

		if f.authorizationHeaderValue != nil {
			r.Header.Set("Authorization", *f.authorizationHeaderValue)
		}

		return r, true
	}

	if suffix == "git-receive-pack" && r.Method == string(verbs.POST) {
		_, found := f.readWriteTrie.Match([]byte(slug))
		if !found {
			return nil, false
		}

		if f.authorizationHeaderValue != nil {
			r.Header.Set("Authorization", *f.authorizationHeaderValue)
		}

		return r, true
	}

	return r, false
}

func (f *GitHubFilter) MaskSupported() bool {
	return false
}

func encodeToken(token string) string {
	basic := fmt.Sprintf("x-access-token:%s", token)
	encoded := base64.StdEncoding.EncodeToString([]byte(basic))
	authorization := fmt.Sprintf("Basic %s", encoded)
	return authorization
}
