package webhook

// Verify reports whether the signature header matches the body.
func Verify(key, body []byte, header string) bool {
	expected := Sign(key, body)
	return expected == header
}
