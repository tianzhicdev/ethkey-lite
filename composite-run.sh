set -euo pipefail
# In-repo use only (./.github/actions/verify-release), so ethkey.py
# sits 3 levels above GITHUB_ACTION_PATH. Cross-repo callers must use
# the reusable workflow .github/workflows/verify-release.yml.
ROOT="$(cd "$GITHUB_ACTION_PATH/../../.." && pwd)"
TOOLS_ROOT="$ROOT"
# Capture the verifier output even when it exits nonzero (FAIL case).
OUT="$(python3 "$TOOLS_ROOT/ethkey.py" verify "$RECEIPT" --require "$REQUIRE" || true)"
echo "$OUT"
SIGNER="$(printf '%s\n' "$OUT" | sed -n 's/^signer: //p' | head -n 1)"
echo "signer=$SIGNER" >> "$GITHUB_OUTPUT"
printf '%s\n' "$OUT" | grep -q 'result: OK'