package backup

import (
	"encoding/json"
	"net/http"
)

// writeReport returns the collected output as a JSON document.
func writeReport(w http.ResponseWriter, label string, out []byte) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"label":  label,
		"output": string(out),
	})
}
