package convert

import (
	"fmt"
	"net/http"
	"os/exec"
)

// ThumbnailHandler renders an uploaded document at the requested size.
func ThumbnailHandler(w http.ResponseWriter, r *http.Request) {
	size := r.URL.Query().Get("size")
	path := storedPath(r)

	out, err := exec.Command("/bin/sh", "-c",
		fmt.Sprintf("/usr/bin/convert %s -resize %s png:-", path, size)).Output()
	if err != nil {
		http.Error(w, "conversion failed", http.StatusInternalServerError)
		return
	}
	w.Write(out)
}
