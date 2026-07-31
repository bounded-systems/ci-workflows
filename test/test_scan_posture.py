#!/usr/bin/env python3
# Tests the scan step's exit-code triage, extracted from osv-scan.yml and run the way
# GitHub actually runs it.
#
# WHY `bash -e` MATTERS ENOUGH TO HAVE ITS OWN TEST FILE:
# GitHub invokes run steps as `bash -e {0}` — errexit comes in on the COMMAND LINE, not
# from anything in the script. The first version of the triage relied on `set -uo
# pipefail` and assumed errexit was off; the shell therefore exited the instant
# osv-scanner returned 1, and `report-only` silently did nothing. A local test that ran
# plain `bash script.sh` passed anyway, because it never reproduced the -e.
#
# So every case here runs through `bash -e`, deliberately. If someone reintroduces the
# bug by dropping `set +e`, the report-only cases fail here instead of on 80 repos.
#
# The property that must hold in every mode: report-only downgrades VULNERABILITY
# findings (exit 1) and nothing else. A tool/network failure (any other non-zero) fails
# hard even under grace — a lane that cannot run must never report green.
import datetime
import pathlib
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "osv-scan.yml"


def extract_scan_step():
    """Pull the scan step's run: block out of the workflow without needing PyYAML."""
    lines = WORKFLOW.read_text().split("\n")
    start = next(
        i for i, l in enumerate(lines)
        if l.strip().startswith("- name: Scan dependencies for known vulnerabilities")
    )
    run_at = next(i for i in range(start, len(lines)) if lines[i].strip() == "run: |")
    base = len(lines[run_at]) - len(lines[run_at].lstrip()) + 2
    body = []
    for l in lines[run_at + 1:]:
        if l.strip() and (len(l) - len(l.lstrip())) < base:
            break
        body.append(l[base:] if len(l) > base else "")
    return "\n".join(body) + "\n"


class ScanPosture(unittest.TestCase):
    def run_step(self, scanner_exit, report_only, grace_expires=""):
        with tempfile.TemporaryDirectory() as td:
            td = pathlib.Path(td)
            stub = td / "osv-scanner"
            stub.write_text(f'#!/bin/sh\necho "stub scanner"\nexit {scanner_exit}\n')
            stub.chmod(0o755)
            script = td / "step.sh"
            script.write_text(extract_scan_step())
            return subprocess.run(
                # -e exactly as GitHub does it. This is the point of the test.
                ["bash", "-e", str(script)],
                capture_output=True, text=True,
                env={
                    "PATH": f"{td}:/usr/bin:/bin",
                    "REPORT_ONLY": report_only,
                    "GRACE_EXPIRES": grace_expires,
                },
            )

    def test_clean_passes_in_both_modes(self):
        for ro in ("false", "true"):
            with self.subTest(report_only=ro):
                self.assertEqual(self.run_step(0, ro).returncode, 0)

    def test_vulns_fail_hard_by_default(self):
        r = self.run_step(1, "false")
        self.assertEqual(r.returncode, 1)
        self.assertNotIn("::warning::", r.stdout)

    def test_vulns_downgraded_under_grace(self):
        r = self.run_step(1, "true")
        self.assertEqual(r.returncode, 0, f"grace did not apply under bash -e: {r.stdout}")
        self.assertIn("::warning::", r.stdout)

    def test_tool_failure_fails_hard_even_under_grace(self):
        # The security-critical case: grace must never mask a scanner that could not run.
        for ro in ("false", "true"):
            for code in (2, 127):
                with self.subTest(report_only=ro, scanner_exit=code):
                    r = self.run_step(code, ro)
                    self.assertEqual(r.returncode, code)
                    self.assertIn("::error::", r.stdout)

    def test_step_actually_clears_errexit(self):
        # Guards the fix directly, so the intent survives a future refactor of the body.
        self.assertRegex(extract_scan_step(), r"(?m)^\s*set \+e\s*$")


class GraceExpiry(unittest.TestCase):
    """Adoption grace must be able to END.

    Unbounded grace is the `required-baseline.yml` failure shape (infra#135): a control
    that reads green while gating nothing. It masked a CVSS 8.8 on `site` for exactly
    that reason, which is why the expiry fails CLOSED in every ambiguous case.

    Dates are computed relative to today rather than hardcoded — a fixed date would turn
    these into tests that silently invert once it passes, which is the same class of rot
    they exist to prevent.
    """

    run_step = ScanPosture.run_step

    @staticmethod
    def _offset(days):
        return (
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=days)
        ).strftime("%Y-%m-%d")

    def test_future_expiry_still_grants_grace(self):
        r = self.run_step(1, "true", self._offset(30))
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("::warning::", r.stdout)
        self.assertIn(self._offset(30), r.stdout)

    def test_expiry_today_still_grants_grace(self):
        # Boundary: grace lasts THROUGH its final day, so an expiry set for today is a
        # warning and not yet a failure. Off-by-one here would fail repos a day early.
        r = self.run_step(1, "true", self._offset(0))
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("::warning::", r.stdout)

    def test_past_expiry_fails_hard(self):
        r = self.run_step(1, "true", self._offset(-1))
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("::error::", r.stdout)
        self.assertIn("EXPIRED", r.stdout)

    def test_absent_expiry_warns_that_grace_is_unbounded(self):
        # Still exit 0 — adoption must never be blocked by the absence of a date — but
        # the run says so every time rather than looking like ordinary grace.
        r = self.run_step(1, "true", "")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("NO EXPIRY", r.stdout)

    def test_malformed_expiry_fails_closed(self):
        # A typo must not be the most permissive setting available.
        for bad in ("soon", "2026-13-01x", "31-10-2026", "2026/10/31", "2026-1-1"):
            with self.subTest(grace_expires=bad):
                r = self.run_step(1, "true", bad)
                self.assertEqual(r.returncode, 1, f"{bad!r} granted grace: {r.stdout}")
                self.assertIn("::error::", r.stdout)

    def test_expiry_never_rescues_a_broken_scanner(self):
        # The security-critical interaction: a tool/network failure fails hard even with
        # grace live and unexpired. Grace downgrades findings, never a lane that could
        # not run.
        for code in (2, 127):
            with self.subTest(scanner_exit=code):
                r = self.run_step(code, "true", self._offset(30))
                self.assertEqual(r.returncode, code)
                self.assertIn("::error::", r.stdout)

    def test_expiry_is_inert_without_report_only(self):
        # Hard-fail posture ignores the date entirely — a stale grace-expires left behind
        # on a cleaned-up repo must not change behaviour in either direction.
        self.assertEqual(self.run_step(1, "false", self._offset(-1)).returncode, 1)
        self.assertEqual(self.run_step(0, "false", self._offset(-1)).returncode, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
