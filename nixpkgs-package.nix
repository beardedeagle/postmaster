# This is a candidate expression for submission to nixpkgs under
# pkgs/by-name/po/postmaster/package.nix
#
# Usage for testing locally (inside a nixpkgs checkout):
#   nix-build -E 'with import ./. {}; callPackage ./path/to/this.nix {}'
#
# Steps before real submission:
#   1. Tag a release in this repo (e.g. v0.1.0) that matches Cargo.toml version.
#   2. Replace the placeholder hash with the real one:
#        nix-prefetch-url --unpack https://github.com/beardedeagle/envelope/archive/refs/tags/v0.1.0.tar.gz
#        (or use nix-update / pkgs/by-name update machinery later)
#   3. Add yourself to maintainers/maintainer-list.nix if not present.
#   4. Set meta.maintainers appropriately.
#   5. Run nixpkgs-review and ensure ofborg builds on linux + darwin.
#
# Notes:
# - The Rust crate lives in the "postmaster/" subdirectory of the repo.
# - We use cargoLock (preferred when a lockfile exists and there are no git deps).
# - No native build inputs needed (pure Rust + rustix; "pure" feature on ecies avoids openssl).

{ lib
, rustPlatform
, fetchFromGitHub
}:

rustPlatform.buildRustPackage rec {
  pname = "postmaster";
  version = "0.1.0";

  src = fetchFromGitHub {
    owner = "beardedeagle";
    repo = "envelope";
    rev = "v${version}";
    hash = "sha256-PLACEHOLDER"; # update after tagging
  };

  sourceRoot = "${src.name}/postmaster";

  cargoLock = {
    lockFile = src + "/postmaster/Cargo.lock";
    # No outputHashes needed — all dependencies come from crates.io.
  };

  meta = {
    description = "postmaster credential bridge: serves decrypted secret values as systemd LoadCredential AF_UNIX sources";
    homepage = "https://github.com/beardedeagle/envelope";
    license = lib.licenses.mit;
    maintainers = with lib.maintainers; [ ]; # replace when you have an entry
    mainProgram = "postmaster";
    platforms = lib.platforms.linux ++ lib.platforms.darwin;
  };
}
