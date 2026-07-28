{
  description = ''
    postmaster — a standalone, format-neutral local secret
    materialization engine. Decrypts encrypted secret inputs at process
    launch time and injects them into a child process via environment
    variables, files, or systemd credentials, then execvp's the target
    binary directly. Supports file-based (.env), HashiCorp Vault, AWS SSM,
    and other secret providers as source/custody backends, with Nix, CDK,
    Ansible, SaltStack, Puppet, Terraform, and OpenTofu as automation targets.
  '';

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
  inputs.rust-overlay.url = "github:oxalica/rust-overlay";
  inputs.rust-overlay.inputs.nixpkgs.follows = "nixpkgs";

  outputs = { self, nixpkgs, rust-overlay }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAll = f: nixpkgs.lib.genAttrs systems
        (system:
          let
            pkgs = import nixpkgs {
              inherit system;
              overlays = [ rust-overlay.overlays.default ];
            };
          in f pkgs);
    in
    {
      packages = forAll (pkgs: rec {
        postmaster = pkgs.callPackage ./package.nix { };
        default = postmaster;
      });

      overlays.default = final: _prev: {
        postmaster = final.callPackage ./package.nix { };
      };

      checks = forAll (pkgs:
        {
          postmaster = self.packages.${pkgs.stdenv.hostPlatform.system}.postmaster;
        });
    };
}
