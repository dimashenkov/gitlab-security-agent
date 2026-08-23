package store

import (
	"context"
	"fmt"
	"net/http"
)

// LookupHandler returns the account matching the caller-supplied region.
func (s *Store) LookupHandler(w http.ResponseWriter, r *http.Request) {
	region := r.URL.Query().Get("region")

	rows, err := s.db.QueryContext(r.Context(),
		fmt.Sprintf("SELECT id, email FROM accounts WHERE region = '%s'", region))
	if err != nil {
		http.Error(w, "lookup failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	writeAccounts(w, rows)
}
