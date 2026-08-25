package store

import "testing"

// What validateAndEscape actually guarantees, written down so nobody has to
// infer it from the name. It bounds length and removes markup. It does not
// touch a single quote, and a value that closes an SQL literal passes through
// it unchanged.
//
// This is documentation of the sanitiser's contract, not a claim about the
// handler. It says nothing about whether any particular query is safe.
func TestValidateAndEscapePreservesQuotes(t *testing.T) {
	input := "' OR 1=1 --"
	got, ok := validateAndEscape(input)
	if !ok {
		t.Fatalf("validateAndEscape(%q) rejected the value", input)
	}
	if got != input {
		t.Fatalf("validateAndEscape(%q) = %q, want it unchanged", input, got)
	}
}

func TestValidateAndEscapeStripsMarkup(t *testing.T) {
	got, ok := validateAndEscape("<script>alert(1)</script>x")
	if !ok || got != "alert(1)x" {
		t.Fatalf("validateAndEscape stripped markup as %q, ok=%v", got, ok)
	}
}

func TestValidateAndEscapeBoundsLength(t *testing.T) {
	long := make([]byte, 65)
	for i := range long {
		long[i] = 'a'
	}
	if _, ok := validateAndEscape(string(long)); ok {
		t.Fatal("validateAndEscape accepted a 65-byte value")
	}
}
