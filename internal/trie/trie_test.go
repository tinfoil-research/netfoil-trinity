package trie

import (
	"testing"

	"github.com/tinfoil-research/netfoil-trinity/internal/verbs"
)

func TestExact(t *testing.T) {
	s := Node{}

	v := make(map[string]struct{})
	v[string(verbs.GET)] = struct{}{}

	err := s.Insert("/a", v)
	if err != nil {
		t.Fatal(err)
	}

	err = s.Insert("/a/b", v)
	if err != nil {
		t.Fatal(err)
	}

	if _, m := s.Match([]byte("")); m {
		t.Errorf("should not match")
	}

	if _, m := s.Match([]byte("/a")); !m {
		t.Errorf("should match")
	}

	if _, m := s.Match([]byte("/a/b")); !m {
		t.Errorf("should match")
	}

	if _, m := s.Match([]byte("/")); m {
		t.Errorf("should not match")
	}

	if _, m := s.Match([]byte("/*")); m {
		t.Errorf("should not match")
	}
}

func TestPrefix(t *testing.T) {
	s := Node{}

	v := make(map[string]struct{})
	v[string(verbs.GET)] = struct{}{}

	err := s.Insert("/a/*", v)
	if err != nil {
		t.Fatal(err)
	}

	if _, m := s.Match([]byte("/a/b")); !m {
		t.Errorf("should match")
	}

	if _, m := s.Match([]byte("/a/")); !m {
		t.Errorf("should match")
	}

	if _, m := s.Match([]byte("/a")); m {
		t.Errorf("should not match")
	}

	if _, m := s.Match([]byte("/")); m {
		t.Errorf("should not match")
	}
}

func TestPrefixAll(t *testing.T) {
	s := Node{}

	v := make(map[string]struct{})
	v[string(verbs.GET)] = struct{}{}

	err := s.Insert("/*", v)
	if err != nil {
		t.Fatal(err)
	}

	if _, m := s.Match([]byte("/")); !m {
		t.Errorf("should match")
	}

	if _, m := s.Match([]byte("/a")); !m {
		t.Errorf("should match")
	}

	if _, m := s.Match([]byte("/b")); !m {
		t.Errorf("should match")
	}

	if _, m := s.Match([]byte("")); m {
		t.Errorf("should not match")
	}
}

func TestVerb(t *testing.T) {
	s := Node{}

	get := make(map[string]struct{})
	get[string(verbs.GET)] = struct{}{}

	post := make(map[string]struct{})
	post[string(verbs.POST)] = struct{}{}

	put := make(map[string]struct{})
	put[string(verbs.PUT)] = struct{}{}

	err := s.Insert("/a", get)
	if err != nil {
		t.Fatal(err)
	}

	err = s.Insert("/a/b", post)
	if err != nil {
		t.Fatal(err)
	}

	err = s.Insert("/a/b/*", put)
	if err != nil {
		t.Fatal(err)
	}

	v, m := s.Match([]byte("/a"))
	if !m || len(v) != 1 {
		t.Errorf("wrong content")
	}

	if _, found := v[string(verbs.GET)]; !found {
		t.Errorf("wrong verb")
	}

	v, m = s.Match([]byte("/a/b"))
	if !m || len(v) != 1 {
		t.Errorf("wrong content")
	}

	if _, found := v[string(verbs.POST)]; !found {
		t.Errorf("wrong verb")
	}

	v, _ = s.Match([]byte("/a/b/c"))
	if !m || len(v) != 1 {
		t.Errorf("wrong content")
	}

	if _, found := v[string(verbs.PUT)]; !found {
		t.Errorf("wrong verb")
	}

	options := make(map[string]struct{})
	options[string(verbs.OPTIONS)] = struct{}{}

	err = s.Insert("/a", options)
	if err != nil {
		t.Fatal(err)
	}

	v, m = s.Match([]byte("/a"))
	if !m || len(v) != 2 {
		t.Errorf("wrong content")
	}

	if _, found := v[string(verbs.OPTIONS)]; !found {
		t.Errorf("wrong verb")
	}

}
