{
  # Local reproducibility face of the CI test suite (ci-workflows#1).
  #
  # `nix flake check` runs EXACTLY the scripts self-test runs — one test suite, two
  # runners. CI itself never installs Nix: the lane's leanness (nothing to install
  # beyond one digest-pinned binary) is a feature, and every test here is stdlib-only
  # Python precisely so both runners agree byte-for-byte. Determinism is enforced by
  # the golden tests, not by the environment; the flake just pins a Python to run
  # them with.
  #
  # THAT PARITY IS THE POINT, SO IT IS LOAD-BEARING: a test that runs in only one
  # runner is a test whose local result cannot be trusted, which is worse than not
  # having it locally at all. When self-test gains a script, add it here in the same
  # change. `test/` should have no file that neither runner executes.
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
        # Mirrors self-test's `converter` job, step for step.
        converter = pkgs.runCommand "converter-tests" { } ''
          cd ${self}
          ${pkgs.python3}/bin/python3 test/test_converter.py
          ${pkgs.python3}/bin/python3 test/check_embed_sync.py
          ${pkgs.python3}/bin/python3 test/test_scan_posture.py
          touch $out
        '';

        # Mirrors self-test's `env-check-digest` job. Separate derivation because it
        # guards a different lane: a red here means env-check-drift would misfire on
        # every ADOPTING repo (their correctly-vendored copies measured against a stale
        # constant), not that the scan lane is broken.
        env-check-digest = pkgs.runCommand "env-check-digest" { } ''
          cd ${self}
          ${pkgs.python3}/bin/python3 test/check_env_check_digest.py
          touch $out
        '';

        # Mirrors self-test's `env-record` job — a third lane again: a red here means
        # env-record would misjudge every adopting repo's checked-in record.
        #
        # THE ONE DERIVATION THAT IS NOT PYTHON-ONLY, deliberately. The lane under test
        # runs the caller's vendored cloud-env-check.mjs to recompute a digest, so a
        # test that stubbed node would be checking a reimplementation of the thing that
        # matters instead of the thing itself — the same mistake test_scan_posture.py
        # documents about failing to reproduce `bash -e`. What is load-bearing above is
        # the PARITY rule, not the language: this runs in both runners, which is what
        # makes a local result trustworthy.
        env-record = pkgs.runCommand "env-record" { } ''
          cd ${self}
          PATH=${pkgs.nodejs}/bin:$PATH ${pkgs.python3}/bin/python3 test/test_env_record.py
          touch $out
        '';

        # Mirrors the SHAPE half of self-test's `template-pins` job. The other half of
        # that job — resolving each SHA with `git cat-file -e` — deliberately has no
        # entry here and cannot have one: this derivation is a store path with no .git
        # and no network, so resolution is impossible by construction, not merely
        # unimplemented.
        #
        # That is the one sanctioned exception to the parity rule above, and it is
        # recorded rather than silent. The rule's purpose — no test whose local result
        # is untrustworthy — is intact: everything runnable offline runs in both
        # runners, and the CI-only half is a strictly additional check, never a
        # substitute for one that runs here.
        template-pins = pkgs.runCommand "template-pins" { } ''
          cd ${self}
          ${pkgs.python3}/bin/python3 test/check_template_pins.py
          touch $out
        '';
      });

      devShells = forAll (pkgs: {
        default = pkgs.mkShell { packages = [ pkgs.python3 ]; };
      });
    };
}
