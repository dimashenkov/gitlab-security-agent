package webhook

import "crypto/hmac"

// Verify reports whether the signature header matches the body.
func Verify(key, body []byte, header string) bool {
	expected := Sign(key, body)
	return hmac.Equal([]byte(expected), []byte(header))
}
