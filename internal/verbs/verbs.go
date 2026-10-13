package verbs

type Verb string

const (
	GET     Verb = "GET"
	POST    Verb = "POST"
	PUT     Verb = "PUT"
	PATCH   Verb = "PATCH"
	DELETE  Verb = "DELETE"
	HEAD    Verb = "HEAD"
	OPTIONS Verb = "OPTIONS"
	TRACE   Verb = "TRACE"
)

func ValidVerb(verb string) bool {
	switch verb {
	case string(GET):
		return true
	case string(POST):
		return true
	case string(PUT):
		return true
	case string(PATCH):
		return true
	case string(DELETE):
		return true
	case string(HEAD):
		return true
	case string(OPTIONS):
		return true
	case string(TRACE):
		return true
	default:
		return false
	}
}
