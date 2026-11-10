{ lib, rust-bin, makeRustPlatform }:

let
  cargoToml = lib.importTOML ./Cargo.toml;
  # Build a rustPlatform from the latest stable rust-overlay toolchain.
  # nixos-25.05's rustPlatform ships rustc 1.86.0, below Cargo.toml's
  # Rust 1.99.1 minimum. rust-overlay provides newer toolchains
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
      ./licenses
      ./src
    ];
  };
  cargoLock.lockFile = ./Cargo.lock;

  meta = {
    description = cargoToml.package.description;
    longDescription = ''
      Postmaster decrypts local dotenv and bundle inputs and delivers values
      through environment variables, files, or systemd credentials before
      replacing the launcher with the application. It also serves credentials
      over local Unix sockets. Deployments provide storage, access controls,
      and service-manager hardening. Encrypted artifacts can be public;
      private keys and plaintext entries need separate protection.
    '';
    homepage = "https://github.com/beardedeagle/postmaster";
    license = lib.licenses.mit;
    mainProgram = "postmaster";
    platforms = lib.platforms.linux ++ lib.platforms.darwin;
    # maintainers = with lib.maintainers; [ ];  # add entry in nixpkgs maintainers/maintainer-list.nix when contributing
  };
}
