# Audit of the whole repository — 2026-08-27

Who did it: Codex, in a new way. Until then I **described** the code to him and
he judged the description. Three defects that nine rounds walked past were found
by a person opening three files — and all three were of one kind: **a sentence
in a docstring that nothing in the code makes true.**

That is why this audit contains not one description of mine. It gives the file
names, says what they are claimed to guarantee, and asks what enforces it.

The result is below, verbatim. **14 blocking and 24 other.** None of it has been
checked by me yet; each item is checked against the code before it is touched,
because Codex has been wrong on a premise before.

The rule this imposes from now on: the round says what the code **ought** to
guarantee and asks what enforces it — never what it does. And some rounds are an
audit over a named area, not a review of my latest change, because a review of
the diff can only find defects in the diff.

---

1. BLOCKER | panel.py:106 | Corrections and `removes_control` use surviving votes as the denominator, allowing one usable vote to move the gate.
2. BLOCKER | gate.py:123 | A non-conclusive profile or incomplete budget stop can exit 0 when `fail_on_incomplete=false`.
3. BLOCKER | models.py:668 | Diff truncation does not make coverage incomplete, and the CLI runner does not propagate the truncation flag.
4. BLOCKER | evidence.py:282 | Diff content can impersonate file headers, while `.strip()` corrupts legal filenames ending in whitespace.
5. BLOCKER | models.py:193 | A finding without distinctive anchors displays a fallback fingerprint that suppression matching does not recognize.
6. BLOCKER | identity.py:30 | Reuse identity omits suppression and runtime policy, and reuse occurs before current suppressions are loaded.
7. BLOCKER | cli.py:463 | A failed head-SHA resolution is recorded as literal `HEAD`, so the artifact does not identify the reviewed commit.
8. BLOCKER | cli.py:76 | Prompt-integrity checking receives filtered and scoped paths, runs after the empty-review return, and misses a prompt directory equal to the repository root.
9. BLOCKER | agent.py:300 | The API runner accepts `end_turn` as completion without `finish_review`, contradicting the prompt’s sole completion signal.
10. BLOCKER | tools/baseline.py:184 | Baseline comparison does not handle the `"error"` outcome and can report an errored case as “No regression.”
11. BLOCKER | models.py:655 | A truncated primary diff remains verdict-neutral and can produce a completed exit-0 review.
12. BLOCKER | .gitlab-ci.yml:220 | `eval-corpus` omits the now-required provider argument and therefore exits before measuring anything.
13. BLOCKER | cli.py:380 | An unavailable explicit or forge-provided head revision silently falls back to local `HEAD`.
14. BLOCKER | github.py:72 | Forge-comment ownership is inferred solely from a public marker, so attacker-authored marker text can divert updates or leave the genuine report stale.

## Non-blocking items

1. HIGH | cli.py:64 | The skip label returns exit 0 before creating an artifact, while the GitLab template can omit the job entirely.
2. HIGH | cli.py:261 | `_nothing_to_review` describes a completely scoped-out change as files excluded by configuration.
3. HIGH | tools/compare_scanners.py:60 | Semgrep and CodeQL results are accepted from output files even when the scanner process exits unsuccessfully.
4. HIGH | tools/artifact.py:17 | Measurement identity uses length-only evidence anchors and can merge unrelated findings through boilerplate lines.
5. HIGH | tools/artifact.py:157 | `target_disposition` returns the first coarse category-and-file match, making finding order decide the measured outcome.
6. MEDIUM | budget.py:85 | `Profile.verifier_turns` is declared, but no code compares verifier turns with that ceiling.
7. MEDIUM | models.py:514 | `STOP_INCONCLUSIVE` is absent from the vocabulary that claims to enumerate incomplete stop reasons.
8. HIGH | budget.py:245 | `Profile.verifiers` is documented as votes per candidate but enforced as a run-wide verifier-session ceiling.
9. LOW | templates/security-scan.yml:78 | The template promises at least two verifiers for high findings although the implementation requires an odd panel and normally uses three.
10. MEDIUM | Dockerfile:3 | The image claims dependencies are pinned although mutable images and bounded dependency ranges are resolved from live repositories.
11. HIGH | .github/workflows/security-review.yml:28 | A mutable third-party action at `@main` receives the Claude API key.
12. MEDIUM | github.py:75 | The comment clients claim they never touch another author’s comment without checking its author.
13. MEDIUM | cli.py:97 | Prompt checking is claimed to precede review decisions but actually follows path filtering and the empty-review return.
14. MEDIUM | cli.py:109 | Reuse is decided before the current suppression file is loaded, contradicting the promised policy identity ordering.
15. MEDIUM | tests/test_github.py:92 | The ownership test uses a foreign comment without the marker and therefore never tests marker impersonation.
16. MEDIUM | tests/test_gitlab.py:82 | The GitLab ownership test likewise proves only that an unrelated marker-free note is ignored.
17. MEDIUM | tests/test_prompt_provenance.py:42 | Prompt-provenance tests omit exclusions, scope, repository-root prompts, and the early empty-review path.
18. MEDIUM | tests/test_cli.py:217 | The skip-label test asserts exit 0 and no model call without checking for an artifact or non-clean status.
19. MEDIUM | tests/test_baseline.py:164 | The incomplete-baseline test exercises `"incomplete"` but not the distinct `"error"` state the comparator drops.
20. LOW | tools.py:678 | Final citation failures are recorded as rejected claims but omitted from some citation-rejection metric counters.
21. LOW | verify.py:176 | The `verified` metric is incremented before `verify_max_findings` removes candidates, overstating how many findings received verification.
22. LOW | budget.py:149 | Direct `Allowance` and `RunBudget` treat the exact tool-call ceiling differently, so equivalent budgets can report different exhaustion states.
23. MEDIUM | config.py:15 | Default exclusions claim lockfile supply-chain risk is caught from manifests, but no deterministic mechanism guarantees that replacement coverage.
24. MEDIUM | tools/corpus_adversary.py:103 | The corpus audit claims between-member cues are unavailable to a reviewer although a model can recognize patch-like surface cues from one member alone.

---

# State as of 2026-08-28

The list above has not been touched and will not be: it is a record of what Codex
said on 2026-08-27, including the places where he was wrong. This part is
**added below** and says what of it has been closed today.

How it was established: by reading the code, not from a summary — neither mine
nor anybody's. The line numbers in the findings are from 2026-08-27 and have
already shifted, so every item was looked up by symbol and by behaviour, not by
line.

**The distinction that is tracked separately:** "the code does the right thing"
and "a test holds it" are not the same. This project has already been bitten by
exactly that — 282 green tests with a broken chain. So every closed item gets the
name of a test and a sentence saying what exactly breaks if the fix is reverted;
where there is no such test, it says **"closed, untested"**, not "closed".

|  | blocking | other | total |
|---|---:|---:|---:|
| closed, a test holds it | 12 | 18 | **30** |
| closed, untested | 1 | 5 | **6** |
| open | 1 | 1 | **2** |
| | 14 | 24 | **38** |

## Open

**Blocking 9 — `agent.py`.** Confirmed open. `src/security_agent/agent.py`
line 288: a response with no `tool_use` block leads to
`stop_reason = STOP_COMPLETED`, and `end_turn` is in `FINISHED_CLEANLY`
(line 83). `ScanOutcome.complete` is `stop_reason == STOP_COMPLETED`, so
`gate.decide` takes the exit-0 path.

What has changed since: the surroundings went from a deny-list to an allowlist
(lines 281‑285), so unnamed reasons such as `model_context_window_exceeded` no
longer reach line 288; and the unsigned case is recorded
(`outcome.finished_explicitly`, line 315) and comes out as a note in the report.
But it is **recorded, not gated** — the comment on lines 309‑314 says so
verbatim.

Important for anyone who reaches out to "fix" it: the state is pinned by tests
*as it is*. `tests/test_finish_review.py::test_a_review_that_just_stops_is_recorded_as_not_signed_off`
asserts `outcome.stop_reason == STOP_COMPLETED`, and
`::test_the_artifact_separates_finishing_from_completing` asserts
`payload["complete"] is True`. That is, the decision is deliberate and is waiting
on a number from twenty real reviews; it is not an oversight.

**Other 7 — `models.py`.** Open, but narrow. `INCOMPLETE_STOPS` (line 632) still
does not contain `STOP_INCONCLUSIVE` and there is no comment saying why. The
tuple is dead code, though — `grep INCOMPLETE_STOPS src/ tools/` returns only its
own definition. Completeness is decided by `ScanOutcome.complete` and by
`gate.NEVER_FORGIVEN = frozenset({STOP_INCONCLUSIVE})`, both of them correctly.
The harm Codex feared — a missing explanation for the reader — is closed:
`STOP_EXPLANATIONS[STOP_INCONCLUSIVE]` exists and is held by
`tests/test_agent_degradation.py::test_every_reason_a_reader_can_meet_has_one_and_not_just_the_listed_ones`,
which walks `vars(models)`, not the tuple. The cheapest closure is one line of
comment or deleting the unused tuple.

## Blocking

| # | state | test that holds it | what breaks if it is reverted |
|---|---|---|---|
| 1 | closed | `test_panel.py::TestALoneSurvivorDecidesNothing::test_it_cannot_correct_a_fact_severity_is_computed_from`, `::test_it_cannot_switch_on_the_removed_control_gate` | the denominator back to `len(usable)` → one vote becomes a majority, `candidate.severity == "low"` breaks; removing `len(usable) == seats` → `candidate.removes_control is False` breaks |
| 2 | closed | `test_gate.py::TestSomeEndingsAreNotTheOperatorsToForgive::test_a_profile_that_cannot_conclude_never_exits_zero`, `::test_a_review_nothing_reached_is_never_a_pass` | without `NEVER_FORGIVEN` → `exit_code == EXIT_ERROR` fails with `forgiving=False`; without `_reviewed_nothing` → it fails for all five stop reasons |
| 3 | closed¹ | `test_truncated_diff_gate.py::TestATruncatedDiffIsNotAPass::test_the_gate_refuses_to_call_it_checked`; `test_runner_claude_code.py::test_a_truncated_diff_travels_with_the_session` | removing `or outcome.coverage.diff_truncated` from `gate._partial` → `EXIT_ERROR` becomes `EXIT_OK`; the fixture raises a real git repo with 4000 lines, it does not hand the flag over by hand |
| 4 | closed | `test_diff_structure.py::TestForgedFileHeader::test_the_whole_chain_still_blocks_the_merge`; `test_path_quoting.py::test_a_header_names_the_file_exactly` | without the `in_hunk` guard → `assert candidate.in_changed_lines` fails ("the added sink was reported as pre-existing"); restoring `.strip()` → the name with a trailing space fails |
| 5 | closed | `test_fingerprint_identity.py::TestTheEscapeHatchWorks::test_a_finding_with_no_distinctive_quote_can_be_suppressed` | a mismatch between the printed and the matched fallback → `kept == []` fails; the test takes the fingerprint out of the finished markdown, writes real YAML and applies it — it goes through the whole chain |
| 6 | closed¹ | `test_identity.py::test_accepting_a_risk_changes_the_review`, `::test_a_setting_that_changes_the_answer_changes_the_identity` | removing `suppressions` from the identity → `digest(before) != digest(after)` fails |
| 7 | closed | `test_cli.py::TestTheReviewedCommitIsNamedOrTheRunFails::test_an_unresolvable_head_is_never_recorded_as_the_word_head`, `::test_an_ordinary_head_still_resolves_to_a_commit` | restoring `or "HEAD"` → the expected `WorkspaceError` never comes, and `len(head_sha) == 40` fails |
| 8 | closed¹ | `test_prompt_provenance.py::test_the_prompt_directory_can_be_the_repository_itself` | restoring the `"./"` prefix in `config.prompt_dir_risk` → `risk.startswith("REFUSE")` fails |
| 9 | **open** | — | see above |
| 10 | closed | `test_baseline.py::test_an_errored_case_is_never_no_regression` | removing the `error` branch → the case catches no branch at all, "No regression" is printed and 0 is returned; `code == 2`, `"No regression" not in printed` and `"errored" in printed` all fail |
| 11 | closed¹ | `test_truncated_diff_gate.py::TestATruncatedDiffIsNotAPass::test_the_gate_refuses_to_call_it_checked`, `::test_the_reason_says_what_to_do_about_it` | the same as 3 — a truncated diff is no longer "checked"; `"first part of the diff" in decision.reason` fails as well |
| 12 | **closed, untested** | none | `.gitlab-ci.yml:226` now passes `--provider anthropic-api`. Nothing in `tests/` reads `.gitlab-ci.yml` — removing the argument leaves the suite green while the job dies on argparse |
| 13 | closed¹ | `test_cli.py::TestTheReviewedCommitIsNamedOrTheRunFails::test_an_explicit_head_that_is_not_in_the_clone_is_refused`, `::test_the_message_says_the_clone_is_the_problem` | restoring the one-line `or "HEAD"` → `pytest.raises(WorkspaceError)` is not raised and `code == 2` fails |
| 14 | closed | `test_github.py::test_a_marker_written_by_somebody_else_is_never_edited`, `::test_the_agents_own_comment_behind_an_impostor_is_still_found` | restoring "the marker is enough" → instead of `POST` a `PATCH` goes out to somebody else's comment 5; the same on the GitLab side in `test_gitlab.py::TestOwnership` |

¹ Closed, but with an untested part — they are listed below.

## Other

| # | state | test that holds it | what breaks if it is reverted |
|---|---|---|---|
| 1 | closed¹ | `test_cli.py::TestSkipHatches::test_a_skipped_review_still_leaves_an_artifact`, `::test_a_skipped_review_overwrites_the_earlier_verdict`, `::test_a_skipped_review_posts_the_note_that_says_so` | a bare `return EXIT_OK` → `(out / "report.md").is_file()` fails, and the finding from the previous run survives on disk |
| 2 | closed | `test_cli.py::TestNothingReviewable::test_a_scoped_out_change_does_not_blame_the_exclude_rules` | back to the single sentence → `"excluded by configuration" not in summary` fails; and all three neighbouring tests go through a real CLI run over a git repo |
| 3 | closed | `test_compare_scanners.py::TestSemgrepExitCode::test_only_a_completed_scan_gets_a_verdict`, `::TestCodeqlExitCode::test_the_sarif_is_only_read_when_analyze_succeeded` | accepting the output on a non-zero code → `incomplete["ok"] is False` fails; the fake scanner writes SARIF on a failed analyze, exactly the shape of the defect |
| 4 | closed | `test_injection_corpus.py::test_a_line_every_function_contains_does_not_merge_two_findings` | a length-only filter → `return nil, err` survives as an anchor, the two findings merge and `introduced_blocks(...) == ["dos:store/lookup.go"]` fails |
| 5 | closed | `test_injection_corpus.py::test_the_target_is_the_finding_the_gate_acted_on_not_the_one_listed_first`, `::test_reordering_the_report_does_not_change_the_target` | taking the first match → `row["fingerprint"] == "fp-target"` and `row["matched"] == 2` fail |
| 6 | closed | `test_budget.py::test_a_profile_declares_no_verifier_turn_ceiling` | the claim was removed, not implemented: restoring the field → `"verifier_turns" not in stored` fails, as does `pytest.raises(TypeError)` |
| 7 | **open** | — | see above |
| 8 | closed | `test_budget.py::test_the_pool_is_a_run_wide_ceiling_and_not_votes_per_candidate` | a pool per candidate instead of per run → all six seats get handed out, while the test expects `[True]*3 + [False]*3` and `check() == STOPPED_VERIFIERS` |
| 9 | **closed, untested** | none | the text in `templates/security-scan.yml` has been reconciled with `verify._votes_for` (at least three, odd panel). `test_config.py::TestTheTemplateAndTheCodeAgreeOnDefaults` reads only `default`, not `description` — restoring "at least two" passes |
| 10 | **closed, untested** | none | `Dockerfile` now says "bounded, not pinned" and explains why. Nothing in `tests/` reads `Dockerfile` |
| 11 | closed | `test_workflows.py::test_an_action_given_a_secret_is_pinned_to_a_commit[security-review.yml]` | restoring `@main` → `assert not offenders` fails; the test demands a ref matching `^[0-9a-f]{40}$` for every step whose `with:` contains `secrets.` |
| 12 | closed | `test_github.py::test_a_marker_written_by_somebody_else_is_never_edited`; `test_gitlab.py::TestOwnership::test_a_marker_written_by_somebody_else_is_never_edited` | as with blocking 14; the opposite direction is held too — `::test_the_agents_own_comment_behind_an_impostor_is_still_found` keeps the fix from turning into "touch nothing" |
| 13 | **closed, untested** | none (only at the level of the helper function) | `cli.py` calls `prompt_dir_risk` before the empty exit and with `raw_changed_paths()`. No test drives `cli._run` — moving the block back passes |
| 14 | closed¹ | `test_identity.py::test_accepting_a_risk_changes_the_review`, `::test_the_artifact_records_what_the_comparison_reads` | removing `suppressions` from the identity → `stored["settings"]["suppressions"] == "abc123"` fails |
| 15 | closed | `test_github.py::test_a_marker_written_by_somebody_else_is_never_edited` | the test now uses **a foreign comment that carries the marker** (`IMPOSTOR`), that is, it measures impersonation; the old markerless case stayed separately as `::test_a_comment_the_agent_did_not_write_is_never_touched` |
| 16 | closed | `test_gitlab.py::TestOwnership::test_a_marker_written_by_somebody_else_is_never_edited` | the same for GitLab; accompanied by `::test_a_note_from_a_renamed_account_is_matched_by_id`, which holds matching by id and not by name |
| 17 | closed¹ | `test_prompt_provenance.py::test_an_exclude_pattern_cannot_answer_the_question`, `::test_a_narrowed_scope_cannot_answer_it_either`, `::test_the_prompt_directory_can_be_the_repository_itself`, `::test_a_change_that_only_edits_a_prompt_is_still_asked_about` | passing `changed_files()` instead of the raw paths → `risk.startswith("REFUSE")` fails in the first two |
| 18 | closed | `test_cli.py::TestSkipHatches::test_a_skipped_review_still_leaves_an_artifact` | the test now checks the artifact and the non-clean state (`"Nothing was examined" in payload["summary"]`), not only exit 0 and zero calls |
| 19 | closed | `test_baseline.py::test_an_errored_case_is_never_no_regression` | the test sets `after[0]["error"]` on an otherwise passing row — a state different from `incomplete`, exactly what Codex said was missing |
| 20 | closed | `test_tools.py::TestEveryRejectionReachesTheCounters` | the counters back in the non-final branch → `citations_rejected_unknown_path == MAX_CITATION_ATTEMPTS` fails (it becomes N‑1), as does `counted == attempts` |
| 21 | closed | `test_verify.py::TestTheVerifiedCountMatchesWhatWasVerified` | counting `len(candidates)` instead of `len(to_verify)` → with 3 candidates and a limit of 1, `metrics.verified == 1` fails (it becomes 3) |
| 22 | closed | `test_budget.py::test_the_run_stops_on_the_ceiling_whichever_route_spent_it` | restoring the stored flag → `direct.check() == through_budget.check()` fails, because the direct route leaves `RunBudget` unaware |
| 23 | **closed, untested** | none | the claim in `config.py` has been withdrawn verbatim and `LIMITATIONS.md` carries the line for the reader. `grep DEFAULT_EXCLUDES tests/` — zero |
| 24 | **closed, untested** | none | the overclaim in `tools/corpus_adversary.py` has been narrowed. `test_corpus_adversary.py` checks only membership in the sets — the old text passes unchanged |

## Closed, but nothing holds it

The six "closed, untested" above — blocking 12 and other 9, 10, 13, 23, 24 —
plus the **parts** that are untested inside otherwise closed items:

- **Blocking 3:** the hop `tools._handle_get_diff` → `session.diff_truncated`
  has no test. Deleting those two lines leaves the suite green while the CLI
  runner's chain quietly reports an untruncated diff.
- **Blocking 11:** the same assignment in `agent.py:324` (the path through the
  API) is held by nothing; its runner half is held separately.
- **Blocking 13:** only the `args.head` branch is tested. The branch from the
  forge (`gl.source_branch_sha`) sits on the same `or` expression —
  `grep source_branch_sha tests/` returns nothing.
- **Blocking 6 and 8, and other 13, 14, 17 — one and the same hole.** The
  ordering of the calls in `cli.py` is pinned by nothing. The prompt-provenance
  check and the reuse guard are correct **as functions** — that much is tested —
  but that `cli.py` calls them in the right place and with the raw paths is not.
  Moving the block back below the empty exit, or deciding reuse before
  `load_rules`, leaves `python3 -m pytest tests/ -q` green. Established by
  reading: every provenance test calls `prompt_dir_risk(...)` directly, and
  `--reuse` is never driven through the CLI in any test.
- **Other 1:** the half in the template (the job is no longer dropped) is read by
  no test.
- **Other 6, a leftover with no consequence:** the docstring in `budget.py`
  still says the argument is "still accepted and ignored" — it is not, the
  constructor raises `TypeError`, as the test itself asserts. A stale sentence,
  with no effect.

The cheapest closure of the big hole is two end-to-end tests through
`cli.main`: one repository with `--prompt-dir` inside the tree, whose change
touches only an excluded prompt file (it must exit non-zero), and one `--reuse`
run in which an accepted risk was added between the two runs (it must not serve
the old artifact).
