package store

import "net/http"

// Routes registers every handler this package exposes. Each one goes through
// Wrap, so no request reaches a handler with an unsanitised parameter.
func (s *Store) Routes(mux *http.ServeMux) {
	mux.HandleFunc("/lookup", Wrap(s.lookupHandler))
}
