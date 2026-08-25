package store

import (
	"database/sql"
	"encoding/json"
	"net/http"
)

type account struct {
	ID    int    `json:"id"`
	Email string `json:"email"`
}

func writeAccounts(w http.ResponseWriter, rows *sql.Rows) {
	out := []account{}
	for rows.Next() {
		var a account
		if err := rows.Scan(&a.ID, &a.Email); err != nil {
			http.Error(w, "read failed", http.StatusInternalServerError)
			return
		}
		out = append(out, a)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}
