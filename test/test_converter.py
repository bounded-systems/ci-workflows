#!/usr/bin/env python3
# Tests for tools/deno-lock-cdx.py. Golden files enforce BYTE-equality — the
# converter's whole contract is that the same lock produces the same bytes on
# any machine, so a golden mismatch is a determinism regression, not a
# formatting nit. Run directly (python3 test/test_converter.py) or via
# `nix flake check`; both execute this same file.
#
# Goldens are named *.golden, never *.cdx.json, so the scan job in self-test
# can never mistake an expected-output file for a real SBOM. The fixture lock
# uses made-up package names so no future real-world advisory can turn the
# self-test red for reasons unrelated to the converter.
import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "tools" / "deno-lock-cdx.py"
FIXTURES = ROOT / "test" / "fixtures"

spec = importlib.util.spec_from_file_location("deno_lock_cdx", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def run_cli(lock_path, out_path):
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(lock_path), str(out_path)],
        capture_output=True,
        text=True,
    )


class ParseKey(unittest.TestCase):
    def test_plain(self):
        self.assertEqual(mod.parse_key("fixture-plain@1.2.3"), ("fixture-plain", "1.2.3"))

    def test_scoped(self):
        self.assertEqual(
            mod.parse_key("@fixture-scope/fixture-scoped@4.5.6"),
            ("@fixture-scope/fixture-scoped", "4.5.6"),
        )

    def test_peer_suffix_stripped(self):
        self.assertEqual(
            mod.parse_key("@hono/node-server@1.19.15_hono@4.12.32"),
            ("@hono/node-server", "1.19.15"),
        )

    def test_underscores_in_name_survive(self):
        # JSR npm-compat mangling puts "__" in names; the "_" that starts a
        # peer suffix only ever appears after the version.
        self.assertEqual(
            mod.parse_key("@jsr/fixture-scope__mirrored@1.0.0"),
            ("@jsr/fixture-scope__mirrored", "1.0.0"),
        )

    def test_prerelease_version(self):
        self.assertEqual(
            mod.parse_key("fixture-plain@2.0.0-rc.1_fixture-peer@9.9.9"),
            ("fixture-plain", "2.0.0-rc.1"),
        )


class Purl(unittest.TestCase):
    def test_scope_at_sign_encoded(self):
        self.assertEqual(
            mod.purl("@fixture-scope/fixture-scoped", "4.5.6"),
            "pkg:npm/%40fixture-scope/fixture-scoped@4.5.6",
        )

    def test_build_metadata_plus_encoded(self):
        self.assertEqual(mod.purl("fixture-plain", "1.0.0+build.7"),
                         "pkg:npm/fixture-plain@1.0.0%2Bbuild.7")


class Golden(unittest.TestCase):
    def test_synthetic_lock_matches_golden_bytes(self):
        golden = (FIXTURES / "synthetic" / "expected-sbom.golden").read_bytes()
        with tempfile.TemporaryDirectory() as td:
            out = pathlib.Path(td) / "out.cdx.json"
            r = run_cli(FIXTURES / "synthetic" / "deno.lock", out)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(out.read_bytes(), golden)
            # The summary line is the lane's honesty about the blind spot —
            # pin its numbers so a parsing regression can't silently shrink it.
            self.assertIn("npm-registry=5 (scanned)", r.stdout)
            self.assertIn("jsr-via-npm-compat=1", r.stdout)
            self.assertIn("jsr-native=1 (NOT scanned", r.stdout)

    def test_double_run_is_byte_identical(self):
        with tempfile.TemporaryDirectory() as td:
            outs = []
            for name in ("a.cdx.json", "b.cdx.json"):
                out = pathlib.Path(td) / name
                r = run_cli(FIXTURES / "synthetic" / "deno.lock", out)
                self.assertEqual(r.returncode, 0, r.stderr)
                outs.append(out.read_bytes())
            self.assertEqual(outs[0], outs[1])


class Edges(unittest.TestCase):
    def _lock(self, td, payload):
        p = pathlib.Path(td) / "deno.lock"
        p.write_text(json.dumps(payload))
        return p

    def test_jsr_only_lock_writes_nothing(self):
        with tempfile.TemporaryDirectory() as td:
            lock = self._lock(td, {
                "version": "5",
                "jsr": {"@fixture-scope/fixture-native@1.0.0": {"integrity": "0"}},
                "npm": {"@jsr/fixture-scope__mirrored@1.0.0": {"integrity": "0"}},
            })
            out = pathlib.Path(td) / "out.cdx.json"
            r = run_cli(lock, out)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertFalse(out.exists())
            self.assertIn("nothing scannable, no SBOM written", r.stdout)

    def test_unsupported_version_warns_but_passes(self):
        with tempfile.TemporaryDirectory() as td:
            lock = self._lock(td, {"version": "3", "npm": {}})
            out = pathlib.Path(td) / "out.cdx.json"
            r = run_cli(lock, out)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertFalse(out.exists())
            self.assertIn("::warning::", r.stdout)

    def test_v4_accepted(self):
        with tempfile.TemporaryDirectory() as td:
            lock = self._lock(td, {"version": "4", "npm": {"fixture-plain@1.2.3": {}}})
            out = pathlib.Path(td) / "out.cdx.json"
            r = run_cli(lock, out)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertTrue(out.exists())

    def test_unparseable_key_fails_loudly(self):
        with tempfile.TemporaryDirectory() as td:
            lock = self._lock(td, {"version": "5", "npm": {"@@garbage": {}}})
            r = run_cli(lock, pathlib.Path(td) / "out.cdx.json")
            self.assertNotEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
