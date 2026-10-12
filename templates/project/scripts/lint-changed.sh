#!/usr/bin/env bash
# ESLint on what changed since the last commit (staged, unstaged and new files): the quick check to
# run before handing work over or committing. `pnpm lint` checks everything.
#
# Not a git pre-commit hook on purpose: .git is read-only in the container, and a hook would be
# project code that the host's git runs. Run this in the container instead. It only reads .git,
# which works on the read-only mount, but needs the git program here.
set -euo pipefail
cd "$(dirname "$0")/.."

if ! command -v git >/dev/null 2>&1; then
  echo "git is not installed in this container, so changed files can't be found: linting everything." >&2
  echo "(Add 'git' to infra/apt-packages.txt and run scripts/sync-env.sh to get the quick check.)" >&2
  exec pnpm exec eslint --max-warnings 0 .
fi

files=()
while IFS= read -r -d '' f; do
  case "$f" in
    *.ts | *.tsx | *.js | *.jsx | *.mjs | *.cjs) [ -f "$f" ] && files+=("./$f") ;;
  esac
done < <(
  { git diff -z --name-only --diff-filter=ACMR HEAD 2>/dev/null || git diff -z --name-only --cached --diff-filter=ACMR
    git ls-files -z --others --exclude-standard; }
)

if [ "${#files[@]}" -eq 0 ]; then
  echo "no changed JavaScript or TypeScript files"
  exit 0
fi
exec pnpm exec eslint --max-warnings 0 --no-warn-ignored "${files[@]}"
