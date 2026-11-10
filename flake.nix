{
  description = ''
    Postmaster decrypts local secret inputs and delivers values through
    environment variables, files, or credentials before execvp replaces the
    launcher with the application. Deployment tools generate exec.json and
    provide local keys, storage, permissions, and service-manager policy.
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
