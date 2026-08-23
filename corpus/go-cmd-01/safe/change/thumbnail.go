package convert

import (
	"net/http"
	"os/exec"
)

// ThumbnailHandler renders an uploaded document at the requested size.
func ThumbnailHandler(w http.ResponseWriter, r *http.Request) {
	size := r.URL.Query().Get("size")
	path := storedPath(r)

	out, err := exec.Command("/usr/bin/convert", path, "-resize", size, "png:-").Output()
	if err != nil {
		http.Error(w, "conversion failed", http.StatusInternalServerError)
		return
	}
	w.Write(out)
}
