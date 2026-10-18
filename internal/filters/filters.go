package filters

import (
	"fmt"
	"io"
	"net/http"
	"regexp"

	"github.com/tinfoil-research/netfoil-trinity/internal/verbs"
)

var regexCharacters = regexp.MustCompile("^[a-zA-Z]+$")

type Filter interface {
	Transform(*http.Request) (*http.Request, bool)
}

type AllowAllFilter struct{}

func (f *AllowAllFilter) Transform(r *http.Request) (*http.Request, bool) {
	return r, true
}

type BasicGETFilter struct{}

func (f *BasicGETFilter) Transform(r *http.Request) (*http.Request, bool) {
	return r, r.Method == string(verbs.GET)
}

func errOnNonEmptyBody(r *http.Request) error {
	data, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}

	if len(data) > 0 {
		return fmt.Errorf("expected non-empty body, got length %d", len(data))
	}

	r.Body = nil

	return nil
}
