package filters

import (
	"fmt"
	"io"
	"net/http"
	"regexp"

	"github.com/tinfoil-research/netfoil-trinity/internal/verbs"
)

var regexCharacters = regexp.MustCompile("^[a-zA-Z]+$")
var regexHeaderRange = regexp.MustCompile("^bytes=([0-9]+-|[0-9]+-[0-9]+|-[0-9]+)(,[0-9]+-|,[0-9]+-[0-9]+|,-[0-9]+)*$")

type Filter interface {
	Transform(*http.Request) (*http.Request, bool)
	MaskSupported() bool
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
	buffer := make([]byte, 1)
	n, err := r.Body.Read(buffer)
	if err != nil && err != io.EOF {
		return err
	}

	if n > 0 {
		return fmt.Errorf("expected non-empty body")
	}

	r.Body = nil

	return nil
}
