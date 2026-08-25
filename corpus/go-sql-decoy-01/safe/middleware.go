package store

import (
	"net/http"
	"regexp"
)

var tagPattern = regexp.MustCompile(`<[^>]*>`)

// validateAndEscape bounds a query parameter and strips markup from it, so a
// value echoed back in an error body cannot carry script. Applied by Wrap to
// every parameter before a handler sees it.
func validateAndEscape(value string) (string, bool) {
	if len(value) > 64 {
		return "", false
	}
	return tagPattern.ReplaceAllString(value, ""), true
}

// Wrap installs the parameter sanitiser in front of a handler.
func Wrap(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		for key, values := range query {
			for i, value := range values {
				clean, ok := validateAndEscape(value)
				if !ok {
					http.Error(w, "parameter too long", http.StatusBadRequest)
					return
				}
				values[i] = clean
			}
			query[key] = values
		}
		r.URL.RawQuery = query.Encode()
		next(w, r)
	}
}
