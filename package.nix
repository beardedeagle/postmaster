{ lib, rust-bin, makeRustPlatform }:

let
  cargoToml = lib.importTOML ./Cargo.toml;
  # Build a rustPlatform from the latest stable rust-overlay toolchain.
  # nixos-25.05's rustPlatform ships rustc 1.86.0, too old for edition 2024
  # + let-chains (requires >= 1.96.1). rust-overlay provides newer toolchains
  # independent of the nixpkgs channel.
  rustPlatform = makeRustPlatform {
    rustc = rust-bin.stable.latest.rust;
    cargo = rust-bin.stable.latest.cargo;
  };
in

rustPlatform.buildRustPackage {
  pname = "postmaster";
  version = cargoToml.package.version;

  src = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.unions [
      ./Cargo.toml
      ./Cargo.lock
      ./src
    ];
  };
  cargoLock.lockFile = ./Cargo.lock;
  # Cargo.lock currently pins ecies to a git rev (see [patch.crates-io] in
  # Cargo.toml, audit 2026-08-02 A7), so importCargoLock additionally needs:
  #   cargoLock.outputHashes."ecies-0.2.11" = "sha256-…";
  # Fill it in on a machine with nix using the fake-hash trick: set a dummy
  # (sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=), run `just
  # flake-check`, and copy the "got:" hash from the error. Drop this again
  # when the upstream ecies PR ships on crates.io and the patch is removed.

  meta = {
    description = cargoToml.package.description;
    longDescription = ''
      postmaster is a dependency-lean Rust daemon (edition 2024; pure-Rust
      crypto with no openssl, no async runtime) that serves decrypted
      values as systemd LoadCredential AF_UNIX sources (with equivalent
      support under nix-darwin). It enables encrypted .env files to be
      treated as ordinary, world-readable Nix store artifacts while
      guaranteeing that plaintext secrets only ever appear inside
      unit-private unswappable credential ramfs.
    '';
    homepage = "https://github.com/beardedeagle/envelope";
    license = lib.licenses.mit;
    mainProgram = "postmaster";
    platforms = lib.platforms.linux ++ lib.platforms.darwin;
    # maintainers = with lib.maintainers; [ ];  # add entry in nixpkgs maintainers/maintainer-list.nix when contributing
  };
}
