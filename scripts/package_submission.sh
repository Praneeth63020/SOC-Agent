#!/usr/bin/env bash
# Build the submission zip from git, so .env, state/, .hermes/, runs/, reports/ and every other untracked or
# ignored file can never be included; then list it, check it and run the secret scanner on the extracted copy.
#
#   scripts/package_submission.sh              # git archive HEAD  -> dist/cehpoint-soc-agent-submission.zip
#   scripts/package_submission.sh --worktree   # the working tree as it would be committed (tracked + untracked
#                                              # files that .gitignore does not exclude), via a temporary git
#                                              # index: no commit is made and no branch or tag moves
set -euo pipefail
cd "$(dirname "$0")/.."
PY="${PYTHON:-$([[ -x .venv/bin/python ]] && echo .venv/bin/python || echo python3)}"
mkdir -p dist
OUT=dist/cehpoint-soc-agent-submission.zip
rm -f "$OUT"
if [[ "${1:-}" == "--worktree" ]]; then
  IDX_DIR=$(mktemp -d)
  trap 'rm -rf "$IDX_DIR"' EXIT
  GIT_INDEX_FILE="$IDX_DIR/index" git add -A
  TREE=$(GIT_INDEX_FILE="$IDX_DIR/index" git write-tree)
  SOURCE="working tree (tree $TREE, not committed; HEAD $(git rev-parse --short HEAD))"
else
  TREE=HEAD
  SOURCE="git HEAD $(git rev-parse --short HEAD)$(git describe --tags --exact-match 2>/dev/null | sed 's/^/ (tag /;s/$/)/')"
fi
git archive --format=zip --prefix=cehpoint-soc-agent/ -o "$OUT" "$TREE"
echo "Built $OUT from $SOURCE"
echo
unzip -Z1 "$OUT" | sed 's#^cehpoint-soc-agent/##' | grep -v -e '/$' -e '^$' | sort > dist/submission-contents.txt
echo "Contents ($(wc -l < dist/submission-contents.txt | tr -d ' ') files; full list: dist/submission-contents.txt):"
sed 's#/.*##' dist/submission-contents.txt | sort | uniq -c | sed 's/^/  /'
# nothing that is local state or a secret may be inside
if grep -E '^(\.env$|\.env\.[^e]|state/|\.hermes/|runs/|reports/|dist/|\.venv/)' dist/submission-contents.txt; then
  echo "FAILED: local state or secrets in the archive (above)"; exit 1
fi
CHECK=$(mktemp -d)
trap 'rm -rf "$CHECK" ${IDX_DIR:-}' EXIT
unzip -q "$OUT" -d "$CHECK"
echo
echo "Secret scan of the extracted copy:"
"$PY" "$CHECK/cehpoint-soc-agent/scripts/check_secrets.py"
echo
echo "OK: $OUT ($(du -h "$OUT" | cut -f1))"
