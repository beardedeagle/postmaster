# Releases

Version-tag pushes and manual runs publish the same release artifacts.
The tag must match the version in its `Cargo.toml`, and its commit must be
reachable from `main`. Manual runs use the workflow on `main` and select
an existing tag.

Each release contains archives for these Rust targets:

| Platform | Target |
| --- | --- |
| Linux x86-64 | `x86_64-unknown-linux-gnu` |
| Linux x86-64, static musl | `x86_64-unknown-linux-musl` |
| Linux ARM64 | `aarch64-unknown-linux-gnu` |
| macOS Intel | `x86_64-apple-darwin` |
| macOS Apple Silicon | `aarch64-apple-darwin` |

The workflow runs release-profile tests on each target, packages the binary
and license, then runs the extracted binary's version and configuration
checks. GitHub attestations identify the workflow that builds each archive.
The publisher checks those attestations, creates the complete SHA-256 manifest,
and attests the manifest and source metadata. It downloads the
draft release and verifies every asset before making the release public.

## Release setup

Create a `release` GitHub environment that allows the `main` branch and
`v*` tags. GitHub signs attestations using the workflow's OpenID Connect
identity. No release signing secret or public-key configuration is required.
Verification trusts GitHub's identity for this repository and release workflow;
attestations do not replace source review or the workflow's source restrictions.

## Publish a version

Commit the version and changelog, merge to `main`, then tag that commit:

```sh
git tag v0.1.0 && git push origin v0.1.0
```

To run manually for an existing tag:

```sh
gh workflow run release.yml --repo beardedeagle/postmaster \
  --ref main -f tag=v0.1.0
```

The workflow refuses to replace an existing release. If verification leaves
a failed draft, inspect it and remove that draft before retrying. Do not move
a published version tag or overwrite its assets. The workflow marks tags
with a prerelease suffix as prereleases.

Pull requests exercise source validation, release tooling and all five
builds. They upload preview archives without attesting or publishing
a release. Local recipes are `just release-test` and
`just release-build <target>`; Python 3.11 or newer is required
for the release-tool tests.

## Verify and install

Install and authenticate the GitHub CLI, then download, verify and install
the selected archive. Verification accepts this repository's release workflow
on `main` or a version tag, and rejects pull-request and feature-branch
identities. This example selects Apple Silicon. The subshell stops on the
first failed command, before extraction or installation:

```sh
(
  set -eu
  version=v0.1.0
  identity='^https://github\.com/beardedeagle/postmaster/\.github/workflows/release\.yml@refs/(heads/main|tags/v[^/]+)$'
  archive="postmaster-${version}-aarch64-apple-darwin.tar.gz"
  base="https://github.com/beardedeagle/postmaster/releases/download/${version}"
  curl --fail --location --remote-name "$base/$archive"
  curl --fail --location --remote-name "$base/SHA256SUMS"
  gh attestation verify SHA256SUMS --repo beardedeagle/postmaster \
    --signer-workflow beardedeagle/postmaster/.github/workflows/release.yml \
    --cert-identity-regex "$identity" \
    --deny-self-hosted-runners
  awk -v file="$archive" '$2 == file { print }' SHA256SUMS > selected.sha256
  test "$(wc -l < selected.sha256 | tr -d ' ')" = 1
  shasum -a 256 -c selected.sha256
  gh attestation verify "$archive" --repo beardedeagle/postmaster \
    --signer-workflow beardedeagle/postmaster/.github/workflows/release.yml \
    --cert-identity-regex "$identity" \
    --deny-self-hosted-runners
  tar -xzf "$archive" postmaster LICENSE
  mkdir -p "$HOME/.local/bin"
  install -m 0755 postmaster "$HOME/.local/bin/postmaster"
)
```

`release.json` records the tagged source commit and complete target set.
Its checksum is covered by the same attested manifest. A manual run's
attestation identifies its triggering `main` revision; `release.json`
identifies the selected tagged source revision.

macOS binaries have no Apple Developer ID signature or notarization.
Attestations provide release authenticity and build provenance; they do not
satisfy Gatekeeper. `curl` downloads and local builds generally
avoid browser-applied quarantine. Browser downloads can still prompt or be
blocked. The workflow does not disable Gatekeeper or remove quarantine.

To build locally instead:

```sh
(
  set -eu
  cargo build --locked --release
  mkdir -p "$HOME/.local/bin"
  install -m 0755 target/release/postmaster "$HOME/.local/bin/postmaster"
)
```
