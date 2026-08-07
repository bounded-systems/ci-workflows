#!/usr/bin/env python3
# Tests --verify-domains' reconcile semantics (ci-workflows#27) hermetically: a
# fake `curl` ahead on PATH answers each probe with a canned http_code, so the
# cases run without network and without touching any real endpoint.
#
# WHY EACH CASE EXISTS: the check's value is that red means "the record and the
# proxy disagree" — in EITHER direction. The direction that motivated #27 is a
# host recorded "expect": "blocked" that starts answering (.github-private#316:
# the record kept reading as blocked after the dialog was updated, and nothing
# machine-visible said so). A version of this check that only failed on the
# blocked-but-expected-reachable direction would have looked identical in that
# incident to one that works. So the reachable-but-expected-blocked case is the
# point, and the matched-blocked case proves adopting the field does not just
# re-arm the old always-red behavior under a new name.
import json
import pathlib
import subprocess
import tempfile
import textwrap
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "tools" / "cloud-env-check.mjs"


def base_config(domains):
    return {
        "handshake": {"variable": "TEST_ENV_CONFIG", "prefix": "TEST_"},
        "networkAccess": {"allowedDomains": domains},
        "environmentVariables": {"TEST_ENV_CONFIG": "placeholder"},
    }


class VerifyDomains(unittest.TestCase):
    def run_verify(self, domains, curl_map):
        """Run --verify-domains with a shimmed curl that answers per curl_map.

        curl_map: {host_substring: http_code}. Hosts not matched answer 000,
        the same value the real script coerces every curl failure to.
        """
        with tempfile.TemporaryDirectory() as td:
            td = pathlib.Path(td)
            cfg = td / "cloud-environment.json"
            cfg.write_text(json.dumps(base_config(domains)))
            cases = "\n".join(
                f'  *{host}*) printf %s {code}; exit 0 ;;'
                for host, code in curl_map.items()
            )
            shim = td / "curl"
            shim.write_text(
                textwrap.dedent(
                    """\
                    #!/bin/sh
                    # Last argument is the probe URL; everything else is flags.
                    for url do :; done
                    case "$url" in
                    {cases}
                    esac
                    printf %s 000
                    """
                ).format(cases=cases)
            )
            shim.chmod(0o755)
            return subprocess.run(
                ["node", str(SCRIPT), "--config", str(cfg), "--verify-domains"],
                capture_output=True,
                text=True,
                env={"PATH": f"{td}:/usr/local/bin:/usr/bin:/bin"},
            )

    # --- the direction #27 exists for ---------------------------------------

    def test_reachable_but_expected_blocked_fails(self):
        r = self.run_verify(
            [
                {"domain": "open.example", "reason": "fixture"},
                {"domain": "walled.example", "reason": "fixture", "expect": "blocked"},
            ],
            {"open.example": "200", "walled.example": "200"},
        )
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("walled.example REACHABLE", r.stdout)
        self.assertIn('"expect": "blocked"', r.stdout)

    def test_blocked_as_recorded_passes(self):
        # The row that retires always-red honest record-keeping: a deliberate
        # recorded-but-absent entry is green, and the summary says why.
        r = self.run_verify(
            [
                {"domain": "open.example", "reason": "fixture"},
                {"domain": "walled.example", "reason": "fixture", "expect": "blocked"},
            ],
            {"open.example": "200"},
        )
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("blocked as recorded", r.stdout)

    # --- the pre-#27 behavior, preserved ------------------------------------

    def test_blocked_but_expected_reachable_fails(self):
        r = self.run_verify(
            [
                {"domain": "open.example", "reason": "fixture"},
                {"domain": "gone.example", "reason": "fixture"},
            ],
            {"open.example": "200"},
        )
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("gone.example BLOCKED", r.stdout)

    def test_all_reachable_passes(self):
        r = self.run_verify(
            [
                {"domain": "a.example", "reason": "fixture"},
                {"domain": "b.example", "reason": "fixture"},
            ],
            {"a.example": "200", "b.example": "302"},
        )
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("allowlist ✓ 2/2", r.stdout)

    # --- guard rails ---------------------------------------------------------

    def test_invalid_expect_refused(self):
        # A typo'd expect would silently fall back to the default and un-fail
        # the check — the same shape as the typo'd container key. Refused.
        r = self.run_verify(
            [{"domain": "a.example", "reason": "fixture", "expect": "bloked"}],
            {"a.example": "200"},
        )
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("bloked", r.stdout)

    def test_dead_network_inconclusive_not_mass_failure(self):
        # All expected-reachable probes at 000 is a dead network, not N revoked
        # grants — and a matched expect:blocked 000 must not veto the guard.
        r = self.run_verify(
            [
                {"domain": "a.example", "reason": "fixture"},
                {"domain": "b.example", "reason": "fixture"},
                {"domain": "walled.example", "reason": "fixture", "expect": "blocked"},
            ],
            {},
        )
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("INCONCLUSIVE", r.stdout)
        self.assertNotIn("✗", r.stdout)

    def test_expect_excluded_from_digest(self):
        # Adopting the field must not move the handshake — "expect" is repo-side
        # annotation like "reason" and "probe", not dialog content.
        def digest_of(domains):
            with tempfile.TemporaryDirectory() as td:
                cfg = pathlib.Path(td) / "c.json"
                cfg.write_text(json.dumps(base_config(domains)))
                return subprocess.run(
                    ["node", str(SCRIPT), "--config", str(cfg), "--print-digest"],
                    capture_output=True, text=True, check=True,
                ).stdout.strip()

        plain = digest_of([{"domain": "a.example", "reason": "fixture"}])
        annotated = digest_of(
            [{"domain": "a.example", "reason": "fixture", "expect": "blocked"}]
        )
        self.assertEqual(plain, annotated)


if __name__ == "__main__":
    unittest.main(verbosity=2)
