package trie

import (
	"fmt"
)

type Node struct {
	match bool
	next  [128]*Node
	verbs map[string]struct{}
}

func (st *Node) Insert(word string, verbs map[string]struct{}) error {
	return st.insert([]byte(word), verbs)
}

func (st *Node) insert(word []byte, verbs map[string]struct{}) error {
	if len(word) == 0 {
		return fmt.Errorf("empty word")
	}

	current := st
	for _, c := range word {
		if c > 127 {
			return fmt.Errorf("invalid character: %d", c)
		}

		if current.next[c] == nil {
			current.next[c] = &Node{}
		}

		current = current.next[c]
	}

	current.match = true
	if current.verbs == nil {
		current.verbs = make(map[string]struct{})
	}

	for v := range verbs {
		current.verbs[v] = struct{}{}
	}

	return nil
}

func (st *Node) Match(word []byte) (map[string]struct{}, bool) {
	if len(word) == 0 {
		return nil, false
	}

	current := st
	for _, c := range word {
		if c > 127 {
			return nil, false
		}

		if current.next[42] != nil {
			return current.next[42].verbs, true
		}

		if current.next[c] == nil {
			return nil, false
		}

		current = current.next[c]
	}

	if current.next[42] != nil {
		return current.next[42].verbs, true
	}

	return current.verbs, current.match
}
