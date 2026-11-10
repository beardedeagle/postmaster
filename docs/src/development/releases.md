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
The publisher checks those attestations, signs the complete SHA-256 manifest
with Minisign, and attests the signed release metadata. It downloads the
draft release and verifies every asset before making the release public.

## Signing setup

Create a `release` GitHub environment that allows the `main` branch and
`v*` tags. Keep the dedicated signing key in that environment. Build jobs
receive no Minisign private key.

Generate the release key outside the checkout, with a private directory
and an offline backup:

```sh
umask 077
mkdir -p "$HOME/.config/postmaster-release"
minisign -G -W \
  -s "$HOME/.config/postmaster-release/minisign.key" \
  -p "$HOME/.config/postmaster-release/minisign.pub"
```

The unattended signer uses a key without a passphrase. GitHub encrypts the
environment secret at rest. Configure the secret and public-key variable
without printing the private key:

```sh
gh secret set MINISIGN_SECRET_KEY --repo beardedeagle/postmaster \
  --env release < "$HOME/.config/postmaster-release/minisign.key"
gh variable set MINISIGN_PUBLIC_KEY --repo beardedeagle/postmaster \
  --env release \
  --body "$(tail -n 1 "$HOME/.config/postmaster-release/minisign.pub")"
```

Publish the public key through a trusted channel before the first release.
Consumers must establish trust in that key independently of the files they
are about to verify. A public key downloaded alongside an archive does not
establish who signed it. Publication fails when either signing input is
missing or the public key does not match the private key.

The signing job can use the release key. A compromised signing workflow can
therefore sign a malicious release; signatures do not replace source review
or the workflow's source restrictions.

## Publish a version

Commit the version and changelog, merge to `main`, then tag that commit:

```sh
git tag v0.1.0
git push origin v0.1.0
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
builds. They upload preview archives without signing, attesting or publishing
a release. Local recipes are `just release-test` and
`just release-build <target>`; Python 3.11 or newer and Minisign are required
for the release-tool tests.

## Verify and install

Download the archive, `SHA256SUMS`, and `SHA256SUMS.minisig` for the chosen
version. This example selects Apple Silicon:

```sh
version=v0.1.0
archive="postmaster-${version}-aarch64-apple-darwin.tar.gz"
base="https://github.com/beardedeagle/postmaster/releases/download/${version}"
curl --fail --location --remote-name "$base/$archive"
curl --fail --location --remote-name "$base/SHA256SUMS"
curl --fail --location --remote-name "$base/SHA256SUMS.minisig"
```

Set `POSTMASTER_RELEASE_PUBLIC_KEY` to the independently trusted public key,
then verify the manifest signature and the selected archive's checksum:

```sh
minisign -V -H -P "$POSTMASTER_RELEASE_PUBLIC_KEY" -m SHA256SUMS
awk -v file="$archive" '$2 == file { print }' SHA256SUMS > selected.sha256
test "$(wc -l < selected.sha256 | tr -d ' ')" = 1
shasum -a 256 -c selected.sha256
gh attestation verify "$archive" --repo beardedeagle/postmaster \
  --signer-workflow beardedeagle/postmaster/.github/workflows/release.yml \
  --deny-self-hosted-runners
tar -xzf "$archive" postmaster LICENSE
mkdir -p "$HOME/.local/bin"
install -m 0755 postmaster "$HOME/.local/bin/postmaster"
```

`release.json` records the tagged source commit and complete target set.
Its checksum is covered by the same signed manifest. A manual run's
attestation identifies its triggering `main` revision; `release.json`
identifies the selected tagged source revision.

macOS binaries have no Apple Developer ID signature or notarization.
Minisign and attestations provide release authenticity and build provenance;
they do not satisfy Gatekeeper. `curl` downloads and local builds generally
avoid browser-applied quarantine. Browser downloads can still prompt or be
blocked. The workflow does not disable Gatekeeper or remove quarantine.

To build locally instead:

```sh
cargo build --locked --release
mkdir -p "$HOME/.local/bin"
install -m 0755 target/release/postmaster "$HOME/.local/bin/postmaster"
```
