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
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "osv-scan.yml"


def extract_step(name):
    """Pull a named step's run: block out of the workflow without needing PyYAML."""
    lines = WORKFLOW.read_text().split("\n")
    start = next(
        i for i, l in enumerate(lines)
        if l.strip().startswith(f"- name: {name}")
    )
    run_at = next(i for i in range(start, len(lines)) if lines[i].strip() == "run: |")
    base = len(lines[run_at]) - len(lines[run_at].lstrip()) + 2
    body = []
    for l in lines[run_at + 1:]:
        if l.strip() and (len(l) - len(l.lstrip())) < base:
            break
        body.append(l[base:] if len(l) > base else "")
    return "\n".join(body) + "\n"


def extract_scan_step():
    return extract_step("Scan dependencies for known vulnerabilities")


def extract_discovery_step():
    return extract_step("Discover scan targets")


class ScanPosture(unittest.TestCase):
    def run_step(self, scanner_exit, report_only, grace_expires="",
                 targets="--lockfile=stub.lock"):
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
                    # The stub dir comes FIRST so it shadows any real osv-scanner;
                    # the ambient PATH after it is what lets bash/git resolve in
                    # both runners (the nix sandbox has no /usr/bin).
                    "PATH": f"{td}:" + os.environ.get("PATH", "/usr/bin:/bin"),
                    "REPORT_ONLY": report_only,
                    "GRACE_EXPIRES": grace_expires,
                    "TARGETS": targets,
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

    def test_empty_target_list_fails_loudly(self):
        # The step is gated on discovery's count != 0, so an empty TARGETS means the
        # gate itself broke. That must be a red, never a scan of nothing — even with
        # a scanner that would have exited 0.
        r = self.run_step(0, "false", targets="")
        self.assertEqual(r.returncode, 1)
        self.assertIn("::error::", r.stdout)
        self.assertNotIn("stub scanner", r.stdout)


class Discovery(unittest.TestCase):
    """The discovery step is the fix for the hooksmith#108 class (.github#103): git,
    not the scanner's directory walk, decides what gets scanned.

    Each case runs the step's run: block against a synthesized git repo. The one that
    matters most is the gitignored-but-tracked lockfile — the exact shape that shipped
    sixteen advisories behind a green check for months, because osv-scanner's walk
    applies .gitignore patterns without git's tracked-file exemption.
    """

    def run_discovery(self, setup):
        with tempfile.TemporaryDirectory() as td:
            td = pathlib.Path(td)
            repo = td / "repo"
            repo.mkdir()
            out = td / "github_output"
            out.touch()
            # HOME is pointed away from the real one so a developer's global git
            # config (core.excludesFile especially) cannot leak into the fixture.
            env = dict(os.environ, HOME=str(td), GITHUB_OUTPUT=str(out))

            def git(*args):
                subprocess.run(["git", *args], cwd=repo, check=True,
                               capture_output=True, env=env)

            git("init", "-q")
            setup(repo, git)
            script = td / "step.sh"
            script.write_text(extract_discovery_step())
            r = subprocess.run(
                ["bash", "-e", str(script)],
                cwd=repo, capture_output=True, text=True, env=env,
            )
            return r, out.read_text()

    def test_gitignored_tracked_lockfile_is_still_discovered(self):
        # THE regression test. Tracked + listed in .gitignore is what blinded the
        # recursive walk; git ls-files must surface it anyway.
        def setup(repo, git):
            (repo / "Cargo.lock").write_text("")
            git("add", "-f", "Cargo.lock")
            (repo / ".gitignore").write_text("Cargo.lock\n")
            git("add", ".gitignore")

        r, out = self.run_discovery(setup)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("count=1", out)
        self.assertIn("--lockfile=Cargo.lock", out)

    def test_no_targets_is_an_explicit_logged_pass(self):
        r, out = self.run_discovery(lambda repo, git: None)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("count=0", out)
        self.assertIn("nothing scannable", r.stdout)

    def test_untracked_lockfile_is_not_a_target(self):
        # Git is the authority in both directions: a lockfile on disk but not
        # tracked is not scanned, rather than depending on walk order and ignores.
        def setup(repo, git):
            (repo / "package-lock.json").write_text("{}")

        r, out = self.run_discovery(setup)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("count=0", out)

    def test_converted_sbom_joins_the_target_list(self):
        # deno-lock.cdx.json is written by the convert step and is untracked by
        # construction — it must be targeted anyway (via find, not ls-files).
        def setup(repo, git):
            (repo / "deno-lock.cdx.json").write_text("{}")

        r, out = self.run_discovery(setup)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("count=1", out)
        self.assertIn("--lockfile=./deno-lock.cdx.json", out)

    def test_tracked_lockfiles_enumerate_across_ecosystems_and_depths(self):
        def setup(repo, git):
            (repo / "go.mod").write_text("")
            (repo / "sub").mkdir()
            (repo / "sub" / "bun.lock").write_text("")
            git("add", "go.mod", "sub/bun.lock")

        r, out = self.run_discovery(setup)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("count=2", out)
        self.assertIn("--lockfile=go.mod", out)
        self.assertIn("--lockfile=sub/bun.lock", out)

    def test_basename_match_is_exact_not_substring(self):
        # `not-a-go.mod` or `go.mod.bak` must not sneak in: a file the scanner
        # cannot parse would red the run, so the match anchors on path boundaries.
        def setup(repo, git):
            (repo / "not-a-go.mod").write_text("")
            (repo / "go.mod.bak").write_text("")
            git("add", "not-a-go.mod", "go.mod.bak")

        r, out = self.run_discovery(setup)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("count=0", out)


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
