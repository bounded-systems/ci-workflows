#!/usr/bin/env python3
# Tests the OPTIONAL handshake block (.github-private#539): in a shared dialog
# exactly one record — the union owner — declares a handshake; sibling records
# omit the block and become probe-only. The change that motivated these cases
# is subtle enough to regress silently: the pre-#539 script treated a missing
# handshake as an early exit 0, which read as harmless ("nothing to check")
# while ALSO taking down domain validation and --verify-domains for that
# record. Each case below pins one edge of the new contract:
#
#   1. absent handshake      → status line, exit 0, and execution REACHES the
#                              domain layer (a typo'd domain list still refuses
#                              — the proof the early exit is gone)
#   2. absent + --print-digest → refusal, exit 1 (no digest exists; env-record
#                              must be dropped, never fed an empty string)
#   3. malformed handshake   → refusal, exit 1 (a typo is not an opt-out)
#   4. digest stability      → a record WITH a handshake digests to the same
#                              value before and after this change (the material
#                              is untouched; only reachability of the code
#                              around it moved)
import json
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "tools" / "cloud-env-check.mjs"


def run_script(config, *args):
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(config, f)
        path = f.name
    return subprocess.run(
        ["node", str(SCRIPT), "--config", path, *args],
        capture_output=True,
        text=True,
    )


DOMAINS = [{"domain": "example.com", "reason": "test"}]


class HandshakeOptional(unittest.TestCase):
    def test_absent_handshake_is_probe_only_not_an_early_exit(self):
        res = run_script({"networkAccess": {"allowedDomains": DOMAINS}})
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("no handshake block", res.stdout)
        # The proof the early exit is gone: a digest-less record with a TYPO'D
        # domain container must still hit the domain layer's refusal.
        bad = run_script({"networkAccess": {"allowedDomians": DOMAINS}})
        self.assertEqual(bad.returncode, 1, bad.stdout + bad.stderr)
        self.assertIn("allowedDomains is missing", bad.stdout)

    def test_absent_handshake_refuses_print_digest(self):
        res = run_script(
            {"networkAccess": {"allowedDomains": DOMAINS}}, "--print-digest"
        )
        self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
        self.assertIn("no digest exists", res.stdout)
        # Nothing 12-hex-shaped may appear — an emitted digest here is exactly
        # the paste-into-the-dialog hazard the refusal exists to prevent.
        self.assertNotRegex(res.stdout, r"\b[0-9a-f]{12}\b")

    def test_malformed_handshake_refuses_loudly(self):
        for block in ({"variable": "X_CONFIG"}, {"prefix": "X_"}, {}):
            res = run_script(
                {"handshake": block, "networkAccess": {"allowedDomains": DOMAINS}}
            )
            self.assertEqual(res.returncode, 1, f"{block}: {res.stdout}")
            self.assertIn("present but missing", res.stdout)

    def test_digest_material_is_unchanged_by_this_feature(self):
        config = {
            "handshake": {"variable": "TEST_ENV_CONFIG", "prefix": "TEST_"},
            "networkAccess": {"allowedDomains": DOMAINS},
            "environmentVariables": {"TEST_ENV_CONFIG": "placeholder"},
        }
        res = run_script(config, "--print-digest")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        # Golden value, computed from the digest material spelled out in the
        # script (handshakeVariable + sorted domains + env entries, handshake
        # value excluded). If this moves, every adopter's dialog value moves —
        # that is a fleet migration, not a refactor, and this test is the
        # tripwire that says so.
        self.assertEqual(res.stdout.strip(), "a54e5044f1b5")


if __name__ == "__main__":
    unittest.main()
