package filters

import (
	"net/http"

	"github.com/tinfoil-research/netfoil-trinity/internal/verbs"
)

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
