#!/usr/bin/env bash
# Ensure a requested Cargo tool runs at its pinned version in later steps.
# Args: crate/binary name (string), version (string), build directory (path).
# Exits nonzero if installation fails or the resulting version differs.
set -euo pipefail

tool="$1"
version="$2"
target_dir="$3"
install_root="${CARGO_INSTALL_ROOT:-${CARGO_HOME:-$HOME/.cargo}}"
tool_bin="$install_root/bin"
export PATH="$tool_bin:$PATH"

version_matches() {
  local reported
  reported="$("$tool" --version 2>/dev/null)" || return 1
  [[ "$reported" == "$tool $version" || "$reported" == "$tool v$version" ]]
}

if ! version_matches; then
  cargo install "$tool" --version "$version" --locked --force \
    --root "$install_root" --target-dir "$target_dir"
  hash -r
fi
if ! version_matches; then
  echo "$tool: expected version $version after installation" >&2
  exit 1
fi
if [[ -n "${GITHUB_PATH:-}" ]]; then
  echo "$tool_bin" >> "$GITHUB_PATH"
fi
"$tool" --version
