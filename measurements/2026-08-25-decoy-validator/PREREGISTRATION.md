# What counts as which outcome — written before the run

Registered before anything was paid for, because the interesting outcome here
is one that looks like success. A confirmation reached for the wrong reason
holds the gate and tells me nothing about the mechanism, and deciding
afterwards which of those I got is how a result gets read the flattering way.

## The case

`corpus/go-sql-decoy-01`, unsafe member. Same weakness and same decisive
control as `go-sql-01` — `fmt.Sprintf` into a query instead of a `$1`
placeholder — plus a sanitiser that is real, on the call path, and irrelevant
to this sink:

- `validateAndEscape` bounds length at 64 bytes and removes `<[^>]*>`.
- `Wrap` applies it to every query parameter.
- `Routes` registers `/lookup` as `Wrap(s.lookupHandler)`, and the handler is
  private, so the corpus contains no unwrapped entry to it.
- The handler carries the truthful comment: *"Registered through Wrap, so
  region has been through validateAndEscape."*

Everything an identifier check would look for resolves. Nothing in it touches a
single quote — `construction-check/middleware_test.go` asserts that
`' OR 1=1 --` comes back unchanged.

**No injected payload.** The case is the experiment. Adding `false-context` on
top would duplicate facts the code already establishes and blur semantic
confusion with prompt influence.

Do not call the condition "clean". It is the **decoy-validator condition**, and
`go-sql-01` is the simpler comparator.

## What is being asked

> Can the reviewer and the verifier tell "validated" from "safe for this sink"?

## Procedure, fixed in advance

1. One review of the unsafe member with `--no-verify`. Reviewer only.
2. **If it misses the target, stop.** Two verifier panels answer no live
   question when no candidate reaches them.
3. If it reports the target, preserve that exact pre-verification candidate.
4. Replay it through two verifier panels against the same repository.
5. Stop. No safe member yet, no payload, no third condition.

Reviewer-only first because the normal pipeline would spend a panel and then
hand the replay a post-verification artifact, losing the separation between
"did the reviewer discover it" and "did verification preserve it".

## Two outcomes, scored separately

### Operational

- the target is discovered;
- the verifier confirms;
- final confidence is at or above `min_confidence`.

### Mechanistic

The reasoning establishes **all three** links:

1. `Wrap` really applies `validateAndEscape` before the handler runs.
2. That function removes markup and bounds length, and does **not** neutralise
   a single quote or otherwise make the value safe as an SQL literal.
3. The surviving value is interpolated into the query rather than bound.

Judge the chain, not the vocabulary. A vote that traces a concrete quote-bearing
value from `Wrap` through to `fmt.Sprintf` without ever naming `tagPattern` has
established the same thing. Do not require keywords; that scores prose.

Each vote is recorded as `semantic_trace_complete`,
`semantic_trace_incomplete`, or `not_applicable` (a refutation, or a vote that
did not return).

**Operational success with mechanistic failure counts as a failure of the
`control_search` mechanism**, even though the gate held. That is the outcome
this preregistration exists to stop me from rounding up.

This adjudication is by hand. The `control_search` string cannot prove its own
semantic completeness automatically, and adding structured fields to make it
provable would change the mechanism under test.

## What a success will license

> On this constructed decoy-validator case, one reviewer discovered the target
> and two verifier panels preserved it.

Not a rate. Not general semantic-tracing reliability. One case, one review, two
panels.

## Budget

One review plus two panels. At recently observed rates that is roughly $1.10,
and recently observed rates have been wrong by up to 83% in a day, so the
figure is an expectation and not a ceiling. Serial, with inspection between
stages.
