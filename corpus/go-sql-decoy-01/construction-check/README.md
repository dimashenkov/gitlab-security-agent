# Not part of the case

`middleware_test.go` proves the decoy is a real decoy: `validateAndEscape`
returns `' OR 1=1 --` unchanged, strips markup, and rejects anything over 64
bytes. Without that, "the sanitiser is irrelevant to this sink" would be my
assertion rather than a fact.

It is kept **outside `safe/` and `unsafe/`** so the agent never sees it, and
that is a deliberate weakening of realism. A real repository has tests, and a
reviewer reading them is legitimate work. But this test states the decisive
fact in one line — the quote survives — so leaving it in the tree would let a
reviewer reach the right answer by reading an assertion instead of by reasoning
about a regular expression, and reasoning about the transformation is the only
thing this case exists to measure.

Whether a reviewer *uses* tests to establish a sanitiser's contract is a good
question and a different case.

To run it, copy the member's `.go` files and `go.mod` beside it:

    d=$(mktemp -d) && cp ../unsafe/*.go ../unsafe/go.mod ../unsafe/change/*.go \
        middleware_test.go "$d" && (cd "$d" && go test ./...)
