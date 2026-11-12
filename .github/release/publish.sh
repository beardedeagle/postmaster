#!/usr/bin/env bash
# Publish only after checking every draft asset's integrity and GitHub attestation.
# Args: tag (string), source commit (SHA), artifact directory (path).
# Requires GH_TOKEN and the GitHub workflow identity variables.
set -euo pipefail

tag="$1"
commit="$2"
directory="$3"
if gh release view "$tag" --repo "$GITHUB_REPOSITORY" >/dev/null 2>&1; then
  echo "Release already exists; refusing to replace its assets" >&2
  exit 1
fi
release_flags=()
if [[ "$tag" == *-* ]]; then
  release_flags+=(--prerelease)
fi
gh release create "$tag" "$directory"/* \
  --repo "$GITHUB_REPOSITORY" --verify-tag --draft \
  --title "$tag" --generate-notes "${release_flags[@]}"
download_dir="$(mktemp -d)"
trap 'rm -rf "$download_dir"' EXIT
gh release download "$tag" --repo "$GITHUB_REPOSITORY" --dir "$download_dir"
just release-verify "$tag" "$commit" "$download_dir"
for artifact in "$download_dir"/*; do
  gh attestation verify "$artifact" --repo "$GITHUB_REPOSITORY" \
    --signer-workflow "$GITHUB_REPOSITORY/.github/workflows/release.yml" \
    --source-digest "$GITHUB_SHA" --source-ref "$GITHUB_REF" \
    --deny-self-hosted-runners
done
gh release edit "$tag" --repo "$GITHUB_REPOSITORY" --draft=false
