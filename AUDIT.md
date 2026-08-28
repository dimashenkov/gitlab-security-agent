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

---

# Състояние към 2026-08-28

Списъкът отгоре не е пипан и няма да бъде: той е запис на това, което Codex
каза на 2026-08-27, включително местата, където е бъркал. Тази част е **добавена
отдолу** и казва какво от него е затворено днес.

Как е установено: с четене на кода, не по обобщение — нито моето, нито ничие.
Номерата на редовете в находките са от 2026-08-27 и вече са изместени, затова
всяко нещо е търсено по символ и по поведение, не по ред.

**Разликата, която се води отделно:** „кодът прави правилното" и „тест го държи"
не са едно и също. Този проект вече е бил ухапан точно от това — 282 зелени
теста при скъсана верига. Затова всяко затворено нещо получава име на тест и
изречение какво точно се чупи, ако поправката се върне назад; където такъв тест
няма, пише **„затворено, нетествано"**, а не „затворено".

|  | блокиращи | други | общо |
|---|---:|---:|---:|
| затворено, тест го държи | 12 | 18 | **30** |
| затворено, нетествано | 1 | 5 | **6** |
| отворено | 1 | 1 | **2** |
| | 14 | 24 | **38** |

## Отворени

**Блокиращо 9 — `agent.py`.** Потвърдено отворено. `src/security_agent/agent.py`
ред 288: отговор без `tool_use` блок води до `stop_reason = STOP_COMPLETED`, а
`end_turn` е в `FINISHED_CLEANLY` (ред 83). `ScanOutcome.complete` е
`stop_reason == STOP_COMPLETED`, тъй че `gate.decide` минава по пътя за exit 0.

Промененото оттогава: наоколо е станало от deny-list на allowlist (редове
281‑285), тъй че неназовани причини като `model_context_window_exceeded` вече не
стигат до ред 288; и неподписаният случай се записва
(`outcome.finished_explicitly`, ред 315) и излиза като бележка в доклада. Но се
**записва, а не се гейтва** — коментарът на редове 309‑314 го казва дословно.

Важно за всеки, който посегне да го „поправи": състоянието е закрепено от
тестове *както е*. `tests/test_finish_review.py::test_a_review_that_just_stops_is_recorded_as_not_signed_off`
твърди `outcome.stop_reason == STOP_COMPLETED`, а
`::test_the_artifact_separates_finishing_from_completing` твърди
`payload["complete"] is True`. Тоест решението е съзнателно и чака число от
двадесет истински прегледа, а не е пропуск.

**Друго 7 — `models.py`.** Отворено, но тясно. `INCOMPLETE_STOPS` (ред 632) още
не съдържа `STOP_INCONCLUSIVE` и няма коментар защо. Кортежът обаче е мъртъв код
— `grep INCOMPLETE_STOPS src/ tools/` дава само собствената му дефиниция.
Пълнотата се решава от `ScanOutcome.complete` и от
`gate.NEVER_FORGIVEN = frozenset({STOP_INCONCLUSIVE})`, и двете вярно. Вредата,
от която Codex се е страхувал — липсващо обяснение за читателя — е затворена:
`STOP_EXPLANATIONS[STOP_INCONCLUSIVE]` съществува и се държи от
`tests/test_agent_degradation.py::test_every_reason_a_reader_can_meet_has_one_and_not_just_the_listed_ones`,
който обхожда `vars(models)`, а не кортежа. Най-евтиното затваряне е един ред
коментар или изтриване на неизползвания кортеж.

## Блокиращи

| # | състояние | тест, който го държи | какво се чупи при връщане назад |
|---|---|---|---|
| 1 | затворено | `test_panel.py::TestALoneSurvivorDecidesNothing::test_it_cannot_correct_a_fact_severity_is_computed_from`, `::test_it_cannot_switch_on_the_removed_control_gate` | знаменателят обратно на `len(usable)` → един глас става мнозинство, чупи се `candidate.severity == "low"`; махане на `len(usable) == seats` → чупи се `candidate.removes_control is False` |
| 2 | затворено | `test_gate.py::TestSomeEndingsAreNotTheOperatorsToForgive::test_a_profile_that_cannot_conclude_never_exits_zero`, `::test_a_review_nothing_reached_is_never_a_pass` | без `NEVER_FORGIVEN` → `exit_code == EXIT_ERROR` пада при `forgiving=False`; без `_reviewed_nothing` → пада за всичките пет причини за спиране |
| 3 | затворено¹ | `test_truncated_diff_gate.py::TestATruncatedDiffIsNotAPass::test_the_gate_refuses_to_call_it_checked`; `test_runner_claude_code.py::test_a_truncated_diff_travels_with_the_session` | махане на `or outcome.coverage.diff_truncated` от `gate._partial` → `EXIT_ERROR` става `EXIT_OK`; фикстурата вдига истинско git repo с 4000 реда, не подава флаг на ръка |
| 4 | затворено | `test_diff_structure.py::TestForgedFileHeader::test_the_whole_chain_still_blocks_the_merge`; `test_path_quoting.py::test_a_header_names_the_file_exactly` | без `in_hunk` пазача → `assert candidate.in_changed_lines` пада („добавеният sink беше отчетен като заварен"); връщане на `.strip()` → пада името с интервал накрая |
| 5 | затворено | `test_fingerprint_identity.py::TestTheEscapeHatchWorks::test_a_finding_with_no_distinctive_quote_can_be_suppressed` | разминаване между отпечатан и съпоставян fallback → `kept == []` пада; тестът вади отпечатъка от готовия markdown, пише истински YAML и го прилага — минава през цялата верига |
| 6 | затворено¹ | `test_identity.py::test_accepting_a_risk_changes_the_review`, `::test_a_setting_that_changes_the_answer_changes_the_identity` | махане на `suppressions` от идентичността → `digest(before) != digest(after)` пада |
| 7 | затворено | `test_cli.py::TestTheReviewedCommitIsNamedOrTheRunFails::test_an_unresolvable_head_is_never_recorded_as_the_word_head`, `::test_an_ordinary_head_still_resolves_to_a_commit` | връщане на `or "HEAD"` → очакваният `WorkspaceError` не идва, и `len(head_sha) == 40` пада |
| 8 | затворено¹ | `test_prompt_provenance.py::test_the_prompt_directory_can_be_the_repository_itself` | връщане на `"./"` префикса в `config.prompt_dir_risk` → `risk.startswith("REFUSE")` пада |
| 9 | **отворено** | — | виж отгоре |
| 10 | затворено | `test_baseline.py::test_an_errored_case_is_never_no_regression` | махане на `error` клона → случаят не хваща никой клон, печата се „No regression" и се връща 0; падат `code == 2`, `"No regression" not in printed`, `"errored" in printed` |
| 11 | затворено¹ | `test_truncated_diff_gate.py::TestATruncatedDiffIsNotAPass::test_the_gate_refuses_to_call_it_checked`, `::test_the_reason_says_what_to_do_about_it` | същото като 3 — отрязан diff вече не е „проверено"; пада и `"first part of the diff" in decision.reason` |
| 12 | **затворено, нетествано** | няма | `.gitlab-ci.yml:226` вече подава `--provider anthropic-api`. Нищо в `tests/` не чете `.gitlab-ci.yml` — махането на аргумента оставя пакета зелен, а job-ът пада на argparse |
| 13 | затворено¹ | `test_cli.py::TestTheReviewedCommitIsNamedOrTheRunFails::test_an_explicit_head_that_is_not_in_the_clone_is_refused`, `::test_the_message_says_the_clone_is_the_problem` | връщане на едноредовия `or "HEAD"` → `pytest.raises(WorkspaceError)` не се вдига и `code == 2` пада |
| 14 | затворено | `test_github.py::test_a_marker_written_by_somebody_else_is_never_edited`, `::test_the_agents_own_comment_behind_an_impostor_is_still_found` | връщане на „маркерът стига" → вместо `POST` тръгва `PATCH` към чуждия коментар 5; същото и от GitLab страна в `test_gitlab.py::TestOwnership` |

¹ Затворено, но с нетествана част — изброени са отдолу.

## Други

| # | състояние | тест, който го държи | какво се чупи при връщане назад |
|---|---|---|---|
| 1 | затворено¹ | `test_cli.py::TestSkipHatches::test_a_skipped_review_still_leaves_an_artifact`, `::test_a_skipped_review_overwrites_the_earlier_verdict`, `::test_a_skipped_review_posts_the_note_that_says_so` | гол `return EXIT_OK` → `(out / "report.md").is_file()` пада, а находката от предното пускане оцелява на диска |
| 2 | затворено | `test_cli.py::TestNothingReviewable::test_a_scoped_out_change_does_not_blame_the_exclude_rules` | връщане към едното изречение → `"excluded by configuration" not in summary` пада; и трите съседни теста минават през истинско CLI пускане върху git repo |
| 3 | затворено | `test_compare_scanners.py::TestSemgrepExitCode::test_only_a_completed_scan_gets_a_verdict`, `::TestCodeqlExitCode::test_the_sarif_is_only_read_when_analyze_succeeded` | приемане на изхода при ненулев код → `incomplete["ok"] is False` пада; фалшивият scanner пише SARIF при провалил се analyze, точно формата на дефекта |
| 4 | затворено | `test_injection_corpus.py::test_a_line_every_function_contains_does_not_merge_two_findings` | филтър само по дължина → `return nil, err` оцелява като котва, двете находки се сливат и `introduced_blocks(...) == ["dos:store/lookup.go"]` пада |
| 5 | затворено | `test_injection_corpus.py::test_the_target_is_the_finding_the_gate_acted_on_not_the_one_listed_first`, `::test_reordering_the_report_does_not_change_the_target` | вземане на първото съвпадение → `row["fingerprint"] == "fp-target"` и `row["matched"] == 2` падат |
| 6 | затворено | `test_budget.py::test_a_profile_declares_no_verifier_turn_ceiling` | твърдението е махнато, не изпълнено: връщане на полето → `"verifier_turns" not in stored` пада, както и `pytest.raises(TypeError)` |
| 7 | **отворено** | — | виж отгоре |
| 8 | затворено | `test_budget.py::test_the_pool_is_a_run_wide_ceiling_and_not_votes_per_candidate` | пул на кандидат вместо на пускане → и шестте места се раздават, а тестът чака `[True]*3 + [False]*3` и `check() == STOPPED_VERIFIERS` |
| 9 | **затворено, нетествано** | няма | текстът в `templates/security-scan.yml` е сверен с `verify._votes_for` (най-малко три, нечетен панел). `test_config.py::TestTheTemplateAndTheCodeAgreeOnDefaults` чете само `default`, не `description` — връщане на „поне два" минава |
| 10 | **затворено, нетествано** | няма | `Dockerfile` вече казва „ограничено, не заковано" и обяснява защо. Нищо в `tests/` не чете `Dockerfile` |
| 11 | затворено | `test_workflows.py::test_an_action_given_a_secret_is_pinned_to_a_commit[security-review.yml]` | връщане на `@main` → `assert not offenders` пада; тестът иска ref по `^[0-9a-f]{40}$` за всяка стъпка, чийто `with:` съдържа `secrets.` |
| 12 | затворено | `test_github.py::test_a_marker_written_by_somebody_else_is_never_edited`; `test_gitlab.py::TestOwnership::test_a_marker_written_by_somebody_else_is_never_edited` | както при блокиращо 14; държи се и обратната посока — `::test_the_agents_own_comment_behind_an_impostor_is_still_found` пази поправката да не стане „не пипай нищо" |
| 13 | **затворено, нетествано** | няма (само на ниво помощна функция) | `cli.py` вика `prompt_dir_risk` преди празния изход и с `raw_changed_paths()`. Никой тест не кара `cli._run` — местенето на блока обратно минава |
| 14 | затворено¹ | `test_identity.py::test_accepting_a_risk_changes_the_review`, `::test_the_artifact_records_what_the_comparison_reads` | махане на `suppressions` от идентичността → `stored["settings"]["suppressions"] == "abc123"` пада |
| 15 | затворено | `test_github.py::test_a_marker_written_by_somebody_else_is_never_edited` | тестът вече ползва **чужд коментар, който носи маркера** (`IMPOSTOR`), тоест мери самозванството; старият случай без маркер остана отделно като `::test_a_comment_the_agent_did_not_write_is_never_touched` |
| 16 | затворено | `test_gitlab.py::TestOwnership::test_a_marker_written_by_somebody_else_is_never_edited` | същото за GitLab; придружено от `::test_a_note_from_a_renamed_account_is_matched_by_id`, което държи съпоставянето по id, а не по име |
| 17 | затворено¹ | `test_prompt_provenance.py::test_an_exclude_pattern_cannot_answer_the_question`, `::test_a_narrowed_scope_cannot_answer_it_either`, `::test_the_prompt_directory_can_be_the_repository_itself`, `::test_a_change_that_only_edits_a_prompt_is_still_asked_about` | подаване на `changed_files()` вместо суровите пътища → `risk.startswith("REFUSE")` пада в първите два |
| 18 | затворено | `test_cli.py::TestSkipHatches::test_a_skipped_review_still_leaves_an_artifact` | тестът вече проверява артефакта и не-чистото състояние (`"Nothing was examined" in payload["summary"]`), не само exit 0 и нула извиквания |
| 19 | затворено | `test_baseline.py::test_an_errored_case_is_never_no_regression` | тестът задава `after[0]["error"]` върху иначе минаващ ред — състояние, различно от `incomplete`, точно каквото Codex каза, че липсва |
| 20 | затворено | `test_tools.py::TestEveryRejectionReachesTheCounters` | броячите обратно в не-финалния клон → `citations_rejected_unknown_path == MAX_CITATION_ATTEMPTS` пада (става N‑1), както и `counted == attempts` |
| 21 | затворено | `test_verify.py::TestTheVerifiedCountMatchesWhatWasVerified` | броене на `len(candidates)` вместо `len(to_verify)` → при 3 кандидата и лимит 1 `metrics.verified == 1` пада (става 3) |
| 22 | затворено | `test_budget.py::test_the_run_stops_on_the_ceiling_whichever_route_spent_it` | връщане на съхранявания флаг → `direct.check() == through_budget.check()` пада, защото прекият път оставя `RunBudget` в неведение |
| 23 | **затворено, нетествано** | няма | твърдението в `config.py` е оттеглено дословно и `LIMITATIONS.md` носи реда за читателя. `grep DEFAULT_EXCLUDES tests/` — нула |
| 24 | **затворено, нетествано** | няма | надтвърдението в `tools/corpus_adversary.py` е стеснено. `test_corpus_adversary.py` проверява само членство в множествата — старият текст минава непроменен |

## Затворено, но нищо не го държи

Шестте „затворено, нетествано" отгоре — блокиращо 12 и други 9, 10, 13, 23, 24 —
плюс **частите**, които са нетествани в иначе затворени неща:

- **Блокиращо 3:** прескокът `tools._handle_get_diff` → `session.diff_truncated`
  няма тест. Изтриването на тези два реда оставя пакета зелен, а веригата на
  CLI runner-а тихо докладва неотрязан diff.
- **Блокиращо 11:** същото присвояване в `agent.py:324` (пътят през API-то) не се
  държи от нищо; runner-ската му половина се държи отделно.
- **Блокиращо 13:** тестван е само клонът `args.head`. Клонът от forge-а
  (`gl.source_branch_sha`) е на същия `or` израз — `grep source_branch_sha tests/`
  не връща нищо.
- **Блокиращо 6 и 8, и други 13, 14, 17 — една и съща дупка.** Подредбата на
  извикванията в `cli.py` не е закрепена от нищо. Проверката за произход на
  prompt-а и пазачът за преизползване са верни **като функции** — това е
  тествано, — но че `cli.py` ги вика на правилното място и със суровите пътища
  не е. Местене на блока обратно под празния изход, или решаване на
  преизползването преди `load_rules`, оставя `python3 -m pytest tests/ -q` зелен.
  Установено с четене: всичките тестове за произход викат `prompt_dir_risk(...)`
  направо, а `--reuse` изобщо не се пуска през CLI в нито един тест.
- **Друго 1:** половината в шаблона (job-ът вече не се изпуска) не се чете от
  никой тест.
- **Друго 6, остатък без последствие:** докстрингът в `budget.py` още казва, че
  аргументът „still accepted and ignored" — не е, конструкторът вдига
  `TypeError`, както самият тест твърди. Изостанало изречение, без ефект.

Най-евтиното затваряне на голямата дупка са два теста от край до край през
`cli.main`: едно repository с `--prompt-dir` вътре в дървото, чиято промяна пипа
само изключен prompt файл (трябва да излезе с ненулев код), и едно `--reuse`
пускане, при което между двете пускания е добавено прието наум допускане
(не трябва да сервира стария артефакт).
