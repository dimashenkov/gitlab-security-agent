"""Artifact-shaped values, built to produce the awkward cases on purpose.

The 2389 hand-written tests already cover the valid row. What they cover badly
is the row that is *almost* a row: a key left out, a `null` where a boolean
belongs, the string `"false"`, a list where an object belongs, two rows for one
case, an offset nobody expected. Every serious defect this repository has
produced is one shape — a check satisfied by the absence of the data it needs —
and absence is exactly what a hand-written fixture supplies least often,
because a person writing a fixture writes the fields they are thinking about.

So these strategies are weighted the other way. `optional()` drops a key
outright; `awkward_bools()` returns a real boolean about a fifth of the time.
Anything built here is JSON-shaped: no NaN, no infinities, string keys only —
an artifact reaches these tools through `json.loads`, and generating values it
could never carry produces counterexamples nobody can act on.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from hypothesis import strategies as st

# A drawn value meaning "leave this key out of the object entirely". Distinct
# from `None`, which is a key that is present and says nothing — the two are
# different inputs to every reader here and one of them is the bug.
ABSENT = object()


def optional(value):
    """`value`, or the key missing altogether."""
    return st.one_of(st.just(ABSENT), value)


def obj(**fields):
    """A dict from named strategies, minus every key that drew `ABSENT`."""
    return st.fixed_dictionaries(fields).map(
        lambda drawn: {k: v for k, v in drawn.items() if v is not ABSENT})


UNKNOWN_KEYS = st.dictionaries(
    st.sampled_from(["note", "_v", "extra", "schema_version"]),
    st.one_of(st.integers(), st.text(max_size=4), st.none()),
    max_size=2)


def with_unknown_keys(base):
    """The same object, sometimes carrying a key no reader knows about.

    A tool that crashes on an unrecognised key cannot read an artifact written
    by a newer version of the thing that produces it.
    """
    return st.builds(lambda body, extra: dict(body, **extra), base, UNKNOWN_KEYS)


# --------------------------------------------------------------- scalar shapes

# A small pool on purpose: duplicates are the point, and two rows for one case
# is the input `read_run` exists to refuse.
CASE_IDS = st.sampled_from(
    ["rb-aaaa-0000-0001", "py-bbbb-0000-0002", "go-cccc-0000-0003"])

MODELS = st.sampled_from(["claude-opus-5", "claude-sonnet-5", "claude-haiku-4"])

DIGESTS = st.sampled_from(["d" * 16, "0" * 16, "no-members", "abc123"])

SHAS = st.sampled_from(["aaa", "bbb", "ccc", ""])


def awkward_bools():
    """Everything that has ever been read as a boolean by mistake.

    `bool(row.get("pair_success"))` reads the missing key as `False` and the
    string `"false"` as `True`; `is not False` reads a key that was never
    written as agreement. Both shipped.
    """
    return st.sampled_from(
        [True, False, "true", "false", "True", "", None, 0, 1, [], {}])


def real_bools():
    return st.booleans()


# ------------------------------------------------------------------ timestamps

OFFSETS = st.sampled_from([-12, -5, -3, 0, 2, 3, 5, 9, 14])


@st.composite
def aware_moments(draw):
    """A real instant, timezone-aware, in some arbitrary offset."""
    base = draw(st.datetimes(
        min_value=datetime(2024, 1, 1),  # noqa: DTZ001 — bound, not an instant
        max_value=datetime(2027, 12, 31),  # noqa: DTZ001
        allow_imaginary=False))
    hours = draw(OFFSETS)
    return base.replace(tzinfo=timezone(timedelta(hours=hours)))


def dated_timestamps():
    """Strings `artifact.instant` is meant to read as a moment."""
    return aware_moments().map(lambda m: m.isoformat())


def undated_timestamps():
    """Everything that must sort nowhere: naive, unparseable, absent, wrong type.

    `Z` is in here deliberately. `datetime.fromisoformat` on the Python this
    package supports (3.9) rejects it, so a producer stamping `...Z` writes a
    row that is silently undated. That is the declared behaviour — a value that
    will not parse is no time at all — not a claim being tested.
    """
    return st.one_of(
        st.just(None),
        st.just(""),
        st.just("2026-08-28T14:00:00"),          # naive
        st.just("2026-08-28T14:00:00Z"),         # not ISO to 3.9
        st.just("yesterday"),
        st.just("2026-13-45T99:00:00+00:00"),
        st.integers(),
        st.lists(st.text(max_size=3), max_size=2),
    )


def timestamps():
    return st.one_of(dated_timestamps(), undated_timestamps())


# --------------------------------------------------------------- artifact parts


def usage_blocks():
    """Tokens, cost, and the completeness flag that has been misread twice."""
    return with_unknown_keys(obj(
        input_tokens=optional(st.one_of(st.integers(0, 10 ** 6), st.none())),
        output_tokens=optional(st.one_of(st.integers(0, 10 ** 6), st.none())),
        cache_read_tokens=optional(st.integers(0, 10 ** 6)),
        cost_usd=optional(st.one_of(
            st.floats(min_value=0, max_value=100, allow_nan=False,
                      allow_infinity=False),
            st.none())),
        complete=optional(awkward_bools()),
    ))


def provenance_blocks(model=MODELS):
    """What produced a review: prompts, schema, version, models, substitution."""
    served = st.one_of(
        st.lists(MODELS, max_size=2),
        st.none(),
        MODELS,                       # a bare string where a list belongs
        st.just([]),
    )
    return with_unknown_keys(obj(
        system_prompt_sha=optional(SHAS),
        verifier_prompt_sha=optional(SHAS),
        schema_sha=optional(SHAS),
        agent_version=optional(st.sampled_from(["0.1.0", "0.2.0", ""])),
        model_requested=optional(st.one_of(model, st.none())),
        model_substituted=optional(awkward_bools()),
        models_served=optional(served),
        models_verified=optional(served),
        auth_method=optional(st.sampled_from(["subscription", "api-key"])),
        reported_cost_usd=optional(st.floats(0, 100, allow_nan=False,
                                             allow_infinity=False)),
    ))


def member_blocks(model=MODELS):
    """One half of a pair: what was configured, and what answered."""
    return with_unknown_keys(obj(
        provenance=optional(st.one_of(provenance_blocks(model), st.none(),
                                      st.just({}), st.lists(st.integers(),
                                                            max_size=1))),
        settings=optional(st.one_of(
            obj(verify=optional(awkward_bools()),
                verify_model=optional(st.one_of(MODELS, st.none())),
                effort=optional(st.sampled_from(["high", "medium"]))),
            st.none())),
    ))


def member_maps():
    """The `members` object — sometimes not both members, sometimes not a map."""
    both = st.fixed_dictionaries({"safe": member_blocks(),
                                  "unsafe": member_blocks()})
    return st.one_of(
        both,
        st.fixed_dictionaries({"safe": member_blocks()}),
        st.just({}),
        st.none(),
        st.lists(member_blocks(), max_size=2),   # a list where an object belongs
    )


CATEGORIES = st.sampled_from(["injection", "authn-authz", "crypto"])
FILES = st.sampled_from(["app/handler.py", "app/other.py"])


def findings(category=None, file_=None):
    return with_unknown_keys(obj(
        category=optional(st.one_of(category or CATEGORIES, st.none())),
        file=optional(st.one_of(file_ or FILES, st.none())),
        fingerprint=optional(st.sampled_from(["f" * 16, "e" * 16])),
        severity=optional(st.sampled_from(["high", "medium", "low"])),
    ))


def finding_lists():
    return st.one_of(
        st.lists(findings(), max_size=2),
        st.none(),
        st.just([]),
        findings(),                              # an object where a list belongs
    )


def case_digests():
    return st.one_of(DIGESTS, st.none())


def result_rows(case_ids=CASE_IDS, digests=None, ran_at=None):
    """One row of a measurement file, in every shape a reader has to survive."""
    return with_unknown_keys(obj(
        case_id=optional(st.one_of(case_ids, st.none(), st.just(""))),
        pair_success=optional(awkward_bools()),
        case_digest=optional(digests if digests is not None else case_digests()),
        ran_at=optional(ran_at if ran_at is not None else timestamps()),
        incomplete=optional(awkward_bools()),
        run_id=optional(st.one_of(st.sampled_from(["r1", "r2"]), st.none())),
        unsafe_recall=optional(awkward_bools()),
        safe_false_positive=optional(awkward_bools()),
        safe_findings=optional(finding_lists()),
        unsafe_findings=optional(finding_lists()),
        members=optional(member_maps()),
        usage=optional(st.one_of(usage_blocks(), st.none())),
    ))


# ----------------------------------------------------------- whole artifacts

# Names that appear both as declared telemetry paths and, deliberately, deeper
# inside the tree. `canonical.telemetry_leaks` exists for exactly the case where
# a restructured artifact moves `usage` one level down and the declared path
# quietly stops matching.
ARTIFACT_KEYS = st.sampled_from([
    "generated_at", "reuse", "usage", "turns_detail", "coverage", "model",
    "provenance", "stop_reason", "stop_detail", "trace_markdown", "findings",
    "model_requested", "session_id", "duration_ms", "a", "b",
])


def json_values(max_leaves=6):
    leaves = st.one_of(
        st.none(), st.booleans(), st.integers(-100, 100),
        st.floats(min_value=-100, max_value=100, allow_nan=False,
                  allow_infinity=False),
        st.text(max_size=4),
    )
    return st.recursive(
        leaves,
        lambda children: st.one_of(
            st.lists(children, max_size=3),
            st.dictionaries(ARTIFACT_KEYS, children, max_size=3)),
        max_leaves=max_leaves)


def tool_call_lists():
    """`coverage.tool_calls[]` — the only declared path with a list in it."""
    return st.lists(
        obj(turn=optional(st.integers(0, 20)),
            name=optional(st.sampled_from(["read", "grep"]))),
        max_size=3)


def artifacts():
    """A whole review artifact: some declared telemetry, some not, some nested."""
    return st.builds(
        lambda body, coverage, prov: dict(
            body,
            **({"coverage": coverage} if coverage is not ABSENT else {}),
            **({"provenance": prov} if prov is not ABSENT else {})),
        st.dictionaries(ARTIFACT_KEYS, json_values(), max_size=6),
        optional(obj(turns=optional(st.integers(0, 20)),
                     tool_calls=optional(tool_call_lists()),
                     files_read=optional(st.lists(st.text(max_size=4),
                                                  max_size=2)))),
        optional(provenance_blocks()),
    )
