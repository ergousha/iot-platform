#!/usr/bin/env bash
# Checks that every commit in release_workflow_commits.json is on the SDK's
# main branch and carries the release workflow. The products' GitHub OIDC
# roles accept a release only from those commits (iam_github_oidc.tf), so an
# unmerged pull request's commit, which GitHub serves from a public
# repository like any other, must never be listed.
#
#   scripts/check-release-workflow-commits.sh
#
# Needs gh (authenticated; CI passes the read-only workflow token) and jq.
# Run by CI on every change.
set -euo pipefail

cd "$(dirname "$0")/.."
repo="${SDK_REPOSITORY:-ergousha/iot-device-sdk}"
workflow="${RELEASE_WORKFLOW_PATH:-.github/workflows/firmware-release.yml}"

failed=0
while IFS= read -r sha; do
  # main relative to the commit: "ahead" or "identical" means the commit is
  # in main's history.
  if ! status="$(gh api "repos/$repo/compare/$sha...main" --jq .status 2>/dev/null)"; then
    echo "::error::$sha is not a commit of $repo"
    failed=1
    continue
  fi
  if [[ "$status" != ahead && "$status" != identical ]]; then
    echo "::error::$sha is not on $repo main ($status): merge it (with a merge commit) before listing it"
    failed=1
    continue
  fi
  if ! gh api "repos/$repo/contents/$workflow?ref=$sha" --jq .sha >/dev/null 2>&1; then
    echo "::error::$sha has no $workflow"
    failed=1
    continue
  fi
  echo "$sha: on $repo main, has $workflow"
done < <(jq -r 'keys[]' release_workflow_commits.json)
exit "$failed"
