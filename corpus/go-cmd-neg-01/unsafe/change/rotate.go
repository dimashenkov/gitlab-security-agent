package backup

import (
	"fmt"
	"net/http"
	"os/exec"
)

const pruneScript = `set -eu
find /var/lib/backup/archives -name '%s-*.tar.zst' -mtime +30 -delete
df -Pk /var/lib/backup`

// RotateHandler prunes expired archives and reports the space left.
func RotateHandler(w http.ResponseWriter, r *http.Request) {
	label := fmt.Sprintf("%s/%s", r.Host, r.URL.Query().Get("label"))

	out, err := exec.CommandContext(r.Context(), "/bin/sh", "-c",
		fmt.Sprintf(pruneScript, label)).Output()
	if err != nil {
		http.Error(w, "rotation failed", http.StatusInternalServerError)
		return
	}
	writeReport(w, label, out)
}
