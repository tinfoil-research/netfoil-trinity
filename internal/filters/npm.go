package filters

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/tinfoil-research/netfoil-trinity/internal/trie"
	"github.com/tinfoil-research/netfoil-trinity/internal/verbs"
)

var regexNPMScope = regexp.MustCompile(`^@[a-z0-9-.]+$`)
var regexNPMPackageName = regexp.MustCompile(`^[a-z0-9-_.]+$`)
var regexNPMVersion = regexp.MustCompile(`[0-9]{1,3}(\.[0-9]{1,3}){0,2}(-(rc|next|beta)\.[0-9])?`)

var regexNPMHeaderPacoteVersion = regexp.MustCompile(`^[0-9]{1,3}(\.[0-9]{1,3}){0,2}$`)
var regexNPMHeaderPacoteIntegrity = regexp.MustCompile(`^sha512-[a-zA-Z0-9/+]+(==)?$`)
var regexNPMHeaderUserAgent = regexp.MustCompile(`^[a-z/0-9. ]+$`)
var regexNPMHeaderIfNoneMatch = regexp.MustCompile(`^[a-zA-Z0-9/"]+$`)
var regexNPMHeaderIfModifiedSince = regexp.MustCompile(`^[A-Za-z]{3}, [0-9]{2} [A-Za-z]{3} [0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2} [A-Z]{3}?$`)

var regexNPMHeaderAccept = regexp.MustCompile(`^(application/vnd\.npm\.install-v1\+json; q=1\.0|application/json|application/json; q=0\.8|\*/\*)$`)

var regexNPMHeaderPacoteReqType = regexp.MustCompile(`^(packument|tarball)$`)
var regexNPMHeaderPacotePkgId = regexp.MustCompile(`^(registry:(@[a-z0-9-.]+/)?[a-z0-9-_.]+|remote:(@[a-z0-9-.]+/)?[a-z0-9-_.]+@https://registry\.npmjs\.org/(@[a-z0-9-.]+/)?[a-z0-9-_.]+/-/[a-z0-9-_.]+-[0-9]+(\.[0-9]+)*(-(rc|next|beta)\.[0-9]+)?\.tgz)$`)
var regexNPMHeaderConnection = regexp.MustCompile(`^keep-alive$`)
var regexNPMHeaderAcceptEncoding = regexp.MustCompile(`^(gzip|deflate)$`)
var regexNPMHeaderAuthType = regexp.MustCompile(`^web$`)
var regexNPMHeaderCommand = regexp.MustCompile(`^install$`)

type NPMFilter struct {
	trie           trie.Node
	allowedHeaders map[string]*regexp.Regexp
	maskRequest    bool
}

type npmArtifact struct {
	scope       *string
	packageName string
	filename    *string
}

func NewNPMFilter(allowedPackages []string, maskRequest bool) (*NPMFilter, error) {
	t := trie.Node{}
	for _, repo := range allowedPackages {
		err := t.Insert(repo, nil)
		if err != nil {
			return nil, err
		}
	}

	return &NPMFilter{
		trie:        t,
		maskRequest: maskRequest,
	}, nil
}

func (f *NPMFilter) Transform(r *http.Request) (*http.Request, bool) {
	artifact, allow, err := f.allowPackage(r)
	if err != nil || !allow {
		return nil, false
	}

	if f.maskRequest {
		rawPath := generateRawPath(artifact)
		path, err := url.PathUnescape(rawPath)
		if err != nil {
			return nil, false
		}

		if path == rawPath {
			rawPath = ""
		}

		r = &http.Request{}
		r.Method = string(verbs.GET)
		r.URL = &url.URL{
			Scheme:  "https",
			Host:    "registry.npmjs.org",
			Path:    path,
			RawPath: rawPath,
		}

		r.Header = make(map[string][]string)

		r.Header.Set("Npm-Auth-Type", "web")
		r.Header.Set("Npm-Command", "install")

		r.Header.Set("Accept-Encoding", "gzip,deflate")
		r.Header.Set("Connection", "keep-alive")

		r.Header.Set("User-Agent", "npm/10.9.8 node/v22.23.1 linux x64 workspaces/false")

		pkgId := generatePacotePkgId(artifact)
		r.Header.Set("Pacote-Pkg-Id", pkgId)
		r.Header.Set("Pacote-Version", "19.0.2")

		if artifact.filename == nil {
			r.Header.Set("Accept", "application/json")
			r.Header.Set("Pacote-Req-Type", "packument")
		} else {
			r.Header.Set("Accept", "*/*")
			r.Header.Set("Pacote-Req-Type", "tarball")
		}
	}

	return r, true
}

func generateRawPath(artifact *npmArtifact) string {
	if artifact.filename == nil {
		id := artifact.packageName
		if artifact.scope != nil {
			id = url.PathEscape(*artifact.scope + "/" + artifact.packageName)
		}

		return fmt.Sprintf("/%s", id)
	}

	if artifact.scope == nil {
		return fmt.Sprintf("/%s/-/%s", artifact.packageName, *artifact.filename)
	}

	return fmt.Sprintf("/%s/%s/-/%s", *artifact.scope, artifact.packageName, *artifact.filename)
}

func generatePacotePkgId(artifact *npmArtifact) string {
	if artifact.filename == nil {
		if artifact.scope == nil {
			return fmt.Sprintf("registry:%s", artifact.packageName)
		}

		return fmt.Sprintf("registry:%s/%s", *artifact.scope, artifact.packageName)
	}

	if artifact.scope == nil {
		return fmt.Sprintf("remote:%s@https://registry.npmjs.org/%s/-/%s", artifact.packageName, artifact.packageName, *artifact.filename)
	}

	return fmt.Sprintf("remote:%s/%s@https://registry.npmjs.org/%s/%s/-/%s", *artifact.scope, artifact.packageName, *artifact.scope, artifact.packageName, *artifact.filename)
}

func (f *NPMFilter) allowPackage(r *http.Request) (*npmArtifact, bool, error) {
	if r.Method != string(verbs.GET) {
		return nil, false, nil
	}

	err := errOnNonEmptyBody(r)
	if err != nil {
		return nil, false, nil
	}

	result := npmArtifact{}

	parts := strings.Split(r.RequestURI, "/")

	if len(parts) < 2 {
		return nil, false, nil
	}

	if parts[0] != "" {
		return nil, false, nil
	}

	if len(parts) == 2 {
		id, err := url.PathUnescape(parts[1])
		if err != nil {
			return nil, false, nil
		}

		idParts := strings.Split(id, "/")
		if len(idParts) == 0 || len(idParts) > 2 {
			return nil, false, nil
		}

		result.packageName = idParts[0]
		if len(idParts) == 2 {
			result.scope = &idParts[0]
			result.packageName = idParts[1]

			if !regexNPMScope.MatchString(*result.scope) {
				return nil, false, nil
			}
		}

		if !regexNPMPackageName.MatchString(result.packageName) {
			return nil, false, nil
		}

		_, found := f.trie.Match([]byte(id))
		if !found {
			return nil, false, nil
		}
	} else if len(parts) == 4 || len(parts) == 5 {
		offset := 0
		if len(parts) == 5 {
			result.scope = &parts[1]
			if !regexNPMScope.MatchString(*result.scope) {
				return nil, false, nil
			}
			offset = 1
		}

		result.packageName = parts[offset+1]
		if !regexNPMPackageName.MatchString(result.packageName) {
			return nil, false, nil
		}

		id := result.packageName
		if result.scope != nil {
			id = *result.scope + "/" + result.packageName
		}

		if parts[offset+2] != "-" {
			return nil, false, nil
		}

		result.filename = &parts[offset+3]
		filenameSuffix, ok := strings.CutPrefix(*result.filename, result.packageName+"-")
		if !ok {
			return nil, false, nil
		}

		versionFromFilename, ok := strings.CutSuffix(filenameSuffix, ".tgz")
		if !ok {
			return nil, false, nil
		}

		if !regexNPMVersion.MatchString(versionFromFilename) {
			return nil, false, nil
		}

		_, found := f.trie.Match([]byte(id))
		if !found {
			return nil, false, nil
		}
	}

	if !verifyNPMHeaders(r, &result) {
		return nil, false, nil
	}

	return &result, true, nil
}

func verifyNPMHeaders(r *http.Request, artifact *npmArtifact) bool {
	for k, v := range r.Header {
		if len(v) != 1 {
			return false
		}

		switch k {
		case "Pacote-Version":
			if !regexNPMHeaderPacoteVersion.MatchString(v[0]) {
				return false
			}
		case "Pacote-Req-Type":
			pacoteReqType := v[0]
			if artifact.filename == nil {
				if pacoteReqType != "packument" {
					return false
				}
			} else {
				if pacoteReqType != "tarball" {
					return false
				}
			}
		case "Pacote-Pkg-Id":
			expected := generatePacotePkgId(artifact)
			if expected != v[0] {
				return false
			}
		case "Pacote-Integrity":
			if !regexNPMHeaderPacoteIntegrity.MatchString(v[0]) {
				return false
			}
		case "Connection":
			if v[0] != "keep-alive" {
				return false
			}
		case "Accept":
			parts := strings.Split(v[0], ", ")
			for _, p := range parts {
				if !regexNPMHeaderAccept.MatchString(p) {
					return false
				}
			}
		case "Accept-Encoding":
			if v[0] != "gzip,deflate" {
				return false
			}
		case "User-Agent":
			if !regexNPMHeaderUserAgent.MatchString(v[0]) {
				return false
			}
		case "Npm-Auth-Type":
			if v[0] != "web" {
				return false
			}
		case "Npm-Command":
			if v[0] != "install" {
				return false
			}
		case "If-None-Match":
			if !regexNPMHeaderIfNoneMatch.MatchString(v[0]) {
				return false
			}
		case "If-Modified-Since":
			if !regexNPMHeaderIfModifiedSince.MatchString(v[0]) {
				return false
			}
		default:
			return false
		}
	}

	return true
}
