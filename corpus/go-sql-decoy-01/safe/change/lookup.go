package store

import (
	"context"
	"net/http"
)

// LookupHandler returns the account matching the caller-supplied region.
// Registered through Wrap, so region has been through validateAndEscape.
func (s *Store) LookupHandler(w http.ResponseWriter, r *http.Request) {
	region := r.URL.Query().Get("region")

	rows, err := s.db.QueryContext(r.Context(),
		"SELECT id, email FROM accounts WHERE region = $1", region)
	if err != nil {
		http.Error(w, "lookup failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	writeAccounts(w, rows)
}
