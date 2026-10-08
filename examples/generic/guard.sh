#!/usr/bin/env bash
# Run each argument as a command, but only if the policy allows it.
#
#   ./guard.sh "npm test" "git push --force origin main"
#
# `sentinel check` exits 0 (allow), 1 (deny) or 3 (confirm).
set -u

for cmd in "$@"; do
  sentinel check "$cmd" >/dev/null
  case $? in
    0) echo "running: $cmd"; bash -c "$cmd" ;;
    3) echo "needs confirmation, skipped: $cmd" >&2 ;;
    *) echo "blocked: $cmd" >&2 ;;
  esac
done
