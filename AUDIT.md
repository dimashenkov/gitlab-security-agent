# Одит на цялото repository — 2026-08-27

Кой го направи: Codex, по нов начин. Дотогава му **описвах** кода и той съдеше
описанието. Три дефекта, които девет кръга подминаха, ги намери човек, като
отвори три файла — и всичките три бяха от един вид: **изречение в докстринг,
което нищо в кода не прави вярно.**

Затова този одит не съдържа нито едно мое описание. Дава имената на файловете,
казва какво се твърди, че гарантират, и пита какво го налага.

Резултатът е отдолу дословно. **14 блокиращи и 24 други.** Нищо от него не е
проверено от мен още; всяко се проверява срещу кода, преди да се пипне, защото
Codex вече е бъркал по предпоставка.

Правило, което това налага занапред: кръгът казва какво кодът **би трябвало** да
гарантира и пита какво го налага — никога какво прави. И някои кръгове са одит
върху назована област, а не преглед на последната ми промяна, защото преглед на
разликата може да намери дефекти само в разликата.

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
