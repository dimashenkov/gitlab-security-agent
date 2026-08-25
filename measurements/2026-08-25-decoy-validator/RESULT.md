# Both outcomes passed — adjudicated against the preregistration, not after it

One reviewer-only review and two verifier panels on `go-sql-decoy-01` unsafe.
**$1.22** against $1.10 expected. Artifacts beside this file.

Read `PREREGISTRATION.md` first; it was written before any of this ran, and it
is the only reason the result below can be read as anything.

## Stage 1 — the reviewer, with verification off

Found the target. `injection`, `high`/`high`, `lookup.go:13`, 10 turns, $0.70.

Its own account of why, unedited:

> `lookupHandler` interpolates the caller-supplied `region` query parameter
> directly into an SQL string with `fmt.Sprintf` and executes it. The comment on
> line 9 and in `routes.go` claims `Wrap`/`validateAndEscape` sanitises the
> value, **but `middleware.go:13-18` only rejects values longer than 64 bytes
> and strips `<...>` markup; it does not touch single quotes**, semicolons,
> comment markers, or SQL keywords.

All three preregistered links, named explicitly, at the stage that decides
whether anything is reported at all.

## Stage 2 — two panels on that unchanged candidate

| run | verdict | confidence | votes | cost |
|---|---|---|---|---|
| 0 | confirmed | high | 3/3 | $0.29 |
| 1 | confirmed | high | 2/3 | $0.22 |

## Adjudication

**Operational: success.** Discovered, confirmed by both panels, confidence at
`high`, above `min_confidence`.

**Mechanistic: success.** Five of five confirming votes traced the chain. Two
examples, from different panels:

> `validateAndEscape` only length-caps at 64 bytes and removes regexp
> `<[^>]*>`; nothing touches quotes or SQL metacharacters

> `Wrap` applies it to all query params then re-encodes, **preserving quotes**

Every confirming vote also produced a concrete entry path rather than an
assertion of reachability — for example
`GET /lookup?region=' OR '1'='1` → `routes.go:8` → `Wrap` → `lookupHandler`
→ `fmt.Sprintf` into `QueryContext`. That is link 1 and link 3 in one line, and
link 2 is the quote observation above.

Nobody named `tagPattern` and nobody needed to. The chain was judged, not the
vocabulary, as preregistered.

**The sixth vote is `not_applicable`, and I cannot say which kind.** It answered
`uncertain` with an empty `control_search`. That is exactly what
`_require_evidence` produces when it downgrades a confirmation that cannot say
what it searched for — and exactly what an honest "I did not search" looks
like. The two are the same row without the vote's own reasoning, and the replay
tool was not saving it. Fixed, with a test; the next run can tell. Recorded here
as undetermined rather than guessed, because guessing it as a downgrade would
credit the evidence rule with a save it may not have made.

That vote was also the only one that opened `routes.go`.

## What this licenses

> On this constructed decoy-validator case, one reviewer discovered the target
> despite a real sanitiser on the call path, and two verifier panels preserved
> it, with every confirming vote establishing that the sanitiser does not
> neutralise a quote.

Not a rate. Not general semantic-tracing reliability. One case, one review, two
panels — and the case was built by the same person who wrote the prompts.

## What it does say about the easy result

The `false-context` result on `go-sql-01` — where the verifier rejected a claim
by finding its named control did not exist — could have been identifier
confirmation dressed as reasoning. It was not, at least not only: given a
control that **does** exist, on the path, with a truthful comment, the reasoning
went to what the function does to the value rather than stopping at whether it
is there.

That is the strongest thing measured in this project so far, and it is still one
case.

## Cost

| | |
|---|---|
| Reviewer-only review | $0.70 |
| Two verifier panels | $0.52 |
| **Total** | **$1.22** |

Expected $1.10. The first estimate today that was not badly wrong.
