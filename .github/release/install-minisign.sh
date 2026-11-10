#!/usr/bin/env bash
# Install the verified official Minisign 0.12 Linux x86-64 binary for release jobs.
set -euo pipefail

tool_dir="$(mktemp -d)"
trap 'rm -rf "$tool_dir"' EXIT
curl --fail --silent --show-error --location --retry 3 \
  https://github.com/jedisct1/minisign/releases/download/0.12/minisign-0.12-linux.tar.gz \
  --output "$tool_dir/minisign.tar.gz"
printf '%s  %s\n' \
  9a599b48ba6eb7b1e80f12f36b94ceca7c00b7a5173c95c3efc88d9822957e73 \
  "$tool_dir/minisign.tar.gz" | sha256sum --check --status
tar -xzf "$tool_dir/minisign.tar.gz" -C "$tool_dir" minisign-linux/x86_64/minisign
mkdir -p "$HOME/.local/bin"
install -m 0755 "$tool_dir/minisign-linux/x86_64/minisign" "$HOME/.local/bin/minisign"
echo "$HOME/.local/bin" >> "$GITHUB_PATH"
"$HOME/.local/bin/minisign" -v
