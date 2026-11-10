#!/usr/bin/env bash
# Sign the complete release manifest using a dedicated, noninteractive key.
# Args: tag (string), source commit (SHA), artifact directory (path).
# Requires MINISIGN_SECRET_KEY and MINISIGN_PUBLIC_KEY; failure stops publication.
set -euo pipefail
umask 077

tag="$1"
commit="$2"
directory="$3"
: "${MINISIGN_SECRET_KEY:?Configure the dedicated release signing secret}"
: "${MINISIGN_PUBLIC_KEY:?Configure the trusted release public key}"
key_dir="$(mktemp -d)"
trap 'rm -rf "$key_dir"' EXIT
printf '%s\n' "$MINISIGN_SECRET_KEY" > "$key_dir/minisign.key"
unset MINISIGN_SECRET_KEY
minisign -S -W -s "$key_dir/minisign.key" -m "$directory/SHA256SUMS" \
  -t "postmaster $tag source $commit"
minisign -V -H -P "$MINISIGN_PUBLIC_KEY" -m "$directory/SHA256SUMS"
