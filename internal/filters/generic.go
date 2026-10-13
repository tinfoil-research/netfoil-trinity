package filters

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/tinfoil-research/netfoil-trinity/internal/trie"
	"github.com/tinfoil-research/netfoil-trinity/internal/verbs"
)

type GenericFilter struct {
	host  string
	trie  trie.Node
	token string
}

func LoadAllGeneric(directory string) (map[string]*GenericFilter, error) {
	genericDirectory := filepath.Join(directory, "generic")
	files, err := os.ReadDir(genericDirectory)
	if err != nil {
		return nil, err
	}

	result := make(map[string]*GenericFilter)

	for _, file := range files {
		err := processFile(genericDirectory, file, result)
		if err != nil {
			return nil, err
		}
	}

	return result, nil
}

func processFile(directory string, file os.DirEntry, m map[string]*GenericFilter) error {
	if !file.IsDir() {
		parts := strings.Split(file.Name(), ":")

		if len(parts) < 2 {
			return fmt.Errorf("too few parts in file name: %s", file.Name())
		}

		domain := parts[0]
		filter, found := m[domain]
		if !found {
			filter = &GenericFilter{
				host: domain,
			}
		}

		v := make(map[string]struct{})
		for _, part := range parts[1:] {
			if !verbs.ValidVerb(part) {
				return fmt.Errorf("invalid verb: %s", part)
			}

			v[part] = struct{}{}
		}

		path := filepath.Join(directory, file.Name())

		file, err := os.Open(path)
		if err != nil {
			return err
		}

		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()

			err := filter.trie.Insert(line, v)
			if err != nil {
				return err
			}
		}

		if err := scanner.Err(); err != nil {
			return err
		}

		m[domain] = filter
	}

	return nil
}

func (f *GenericFilter) Transform(r *http.Request) (*http.Request, bool) {
	if r.Host != f.host {
		return nil, false
	}

	v, match := f.trie.Match([]byte(r.RequestURI))
	if !match {
		return nil, false
	}

	if _, verbFound := v[r.Method]; !verbFound {
		return nil, false
	}

	return r, true
}
