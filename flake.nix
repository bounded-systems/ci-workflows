{
  # Local reproducibility face of the CI test suite (ci-workflows#1).
  #
  # `nix flake check` runs EXACTLY the two scripts self-test's converter job runs —
  # one test suite, two runners. CI itself never installs Nix: the lane's leanness
  # (nothing to install beyond one digest-pinned binary) is a feature, and the
  # converter is stdlib-only Python precisely so both runners agree byte-for-byte.
  # Determinism is enforced by the golden tests, not by the environment; the flake
  # just pins a Python to run them with.
  #
  # flake.lock: generate once with `nix flake lock` on a machine with Nix — the
  # session that authored this had none. Until it is committed, the nixpkgs input
  # below floats within the release branch; the goldens are what hold either way.
  description = "bounded-systems/ci-workflows — converter tests, locally reproducible";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAll = f: nixpkgs.lib.genAttrs systems (s: f nixpkgs.legacyPackages.${s});
    in
    {
      checks = forAll (pkgs: {
        converter = pkgs.runCommand "converter-tests" { } ''
          cd ${self}
          ${pkgs.python3}/bin/python3 test/test_converter.py
          ${pkgs.python3}/bin/python3 test/check_embed_sync.py
          touch $out
        '';
      });

      devShells = forAll (pkgs: {
        default = pkgs.mkShell { packages = [ pkgs.python3 ]; };
      });
    };
}
