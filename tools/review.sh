#!/usr/bin/env bash
# Review a branch against its base, then file the result in the journal.
#
# For running the agent on your own work, without CI. The GitLab job exists for
# merge requests; this exists because the decision the trial is supposed to
# answer — is this worth its cost on my code — needs the tool in the loop
# before any of that.
#
#     tools/review.sh                      # current branch against main
#     tools/review.sh --base v1.2.0
#     tools/review.sh --noticed "the region param goes into a query unescaped"
#
# Advisory by construction: --no-comment, no GitLab token, nothing blocks. The
# exit code is the agent's, and 2 still means the review did not finish.
#
# Read your own diff FIRST and pass what you saw as --noticed. If you read the
# report first, a useful finding can no longer be told apart from one you would
# have found anyway, and the month of journal entries answers a different
# question than the one it was set up for.

set -euo pipefail

BASE=""
NOTICED=""
OUT=".security-scan"

while [ $# -gt 0 ]; do
    case "$1" in
        --base)    BASE="$2"; shift 2 ;;
        --noticed) NOTICED="$2"; shift 2 ;;
        --output)  OUT="$2"; shift 2 ;;
        -h|--help) sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

root=$(git rev-parse --show-toplevel)
cd "$root"

if [ -z "$BASE" ]; then
    # The commit this branch actually left from, not the tip of main — a diff
    # against a moved tip includes everyone else's work and the review then
    # reports things you did not write.
    default=$(git symbolic-ref --quiet --short refs/remotes/origin/HEAD 2>/dev/null || echo origin/main)
    BASE=$(git merge-base HEAD "$default" 2>/dev/null || git merge-base HEAD main)
fi

head=$(git rev-parse HEAD)
short=$(git rev-parse --short HEAD)

if [ "$BASE" = "$head" ]; then
    echo "base and head are the same commit — nothing to review" >&2
    exit 2
fi

if [ -z "${ANTHROPIC_API_KEY:-}" ]; then
    echo "ANTHROPIC_API_KEY is not set. A review costs roughly \$0.60-3.65 and" >&2
    echo "the spread is 4-6x, so set a spending limit on the account too." >&2
    exit 2
fi

echo "reviewing ${BASE:0:12}..${short}  ($(git rev-list --count "$BASE..HEAD") commit(s), $(git diff --name-only "$BASE..HEAD" | wc -l | tr -d ' ') file(s))"

set +e
PYTHONPATH=src python3 -m security_agent \
    --repo "$root" --mode diff --base "$BASE" --head "$head" \
    --no-comment --output-dir "$OUT"
code=$?
set -e

if [ -f "$OUT/findings.json" ]; then
    PYTHONPATH=src python3 tools/journal.py add "$OUT/findings.json" \
        --ref "$short" ${NOTICED:+--noticed "$NOTICED"}
    echo
    echo "Report: $OUT/report.md"
    echo "Judge each finding in journal/$short/verdict.yml — a finding nobody"
    echo "has judged counts for nothing, in either direction."
else
    echo "no artifact was written; the review did not reach one" >&2
fi

exit $code
