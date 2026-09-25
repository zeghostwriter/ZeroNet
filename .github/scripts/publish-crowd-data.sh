#!/usr/bin/env bash
# Put files on the `crowd-data` branch, keeping the ones already there.
#
#   publish-crowd-data.sh rankings.json [verified.txt ...]
#
# The branch holds a single commit, replaced every time: the history of
# which servers worked when is not worth keeping, and it would grow the
# repository by a copy on every run. The workflows that call this share one
# concurrency group, so two never replace the commit at the same time.
set -euo pipefail

# CROWD_DATA_REMOTE is for trying this against a local repository.
repo_url="${CROWD_DATA_REMOTE:-https://x-access-token:${GITHUB_TOKEN}@github.com/${GITHUB_REPOSITORY}.git}"
work=$(mktemp -d)
git -C "$work" init -q -b crowd-data
if git -C "$work" fetch -q --depth 1 "$repo_url" crowd-data 2>/dev/null; then
  git -C "$work" checkout -q FETCH_HEAD -- .
fi
for file in "$@"; do
  cp "$file" "$work/$(basename "$file")"
done
cd "$work"
git config user.name "github-actions[bot]"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
git add -A
git commit -q -m "Crowd data $(date -u +%Y-%m-%dT%H:%MZ)"
git push -q --force "$repo_url" HEAD:crowd-data
# Ask the jsDelivr mirror to drop its copies, which it otherwise keeps for
# up to a day.
for file in "$@"; do
  curl -fsS --max-time 20 "https://purge.jsdelivr.net/gh/${GITHUB_REPOSITORY}@crowd-data/$(basename "$file")" > /dev/null || true
done
