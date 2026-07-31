#!/usr/bin/env python3
# Tests the env-record step, extracted from env-record.yml and run the way GitHub runs
# it (`bash -e`), against synthesized records.
#
# WHY EACH CASE EXISTS: this lane's whole value is that it FAILS on a stale digest. A
# version that passed unconditionally would look identical in CI to one that works — the
# same hollow-green shape the lane is meant to remove. So the negative cases are the
# point, and the positive case only proves it is not stuck red.
#
# The record's correct digest is a pure function of its own contents, so every fixture
# here computes its expected value with the real script rather than hardcoding one.
import json
import pathlib
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "env-record.yml"
SCRIPT = ROOT / "tools" / "cloud-env-check.mjs"

BASE = {
    "handshake": {"variable": "TEST_ENV_CONFIG", "prefix": "TEST_"},
    "networkAccess": {
        "allowedDomains": [
            {"domain": "example.com", "reason": "fixture"},
            {"domain": "example.org", "reason": "fixture"},
        ]
    },
    # The handshake key must be PRESENT when the digest is computed. Its VALUE is
    # excluded from the hash (hashing it would be circular) but its NAME is not, so a
    # record whose digest was computed before the key was added disagrees with itself.
    # That is a real trap for anyone maintaining these files by hand, and the reason the
    # fixtures below seed a placeholder first and overwrite it after.
    "environmentVariables": {"TEST_ENV_CONFIG": "placeholder"},
}


def extract_step():
    """Pull the verify step's run: block out of the workflow without needing PyYAML."""
    lines = WORKFLOW.read_text().split("\n")
    start = next(
        i for i, l in enumerate(lines)
        if l.strip().startswith("- name: Recorded handshake digest")
    )
    run_at = next(i for i in range(start, len(lines)) if lines[i].strip() == "run: |")
    base = len(lines[run_at]) - len(lines[run_at].lstrip()) + 2
    body = []
    for l in lines[run_at + 1:]:
        if l.strip() and (len(l) - len(l.lstrip())) < base:
            break
        body.append(l[base:] if len(l) > base else "")
    return "\n".join(body) + "\n"


class EnvRecord(unittest.TestCase):
    def run_step(self, config_obj, *, script_name="cloud-env-check.mjs"):
        with tempfile.TemporaryDirectory() as td:
            td = pathlib.Path(td)
            shutil.copy(SCRIPT, td / script_name)
            cfg = td / "cloud-environment.json"
            cfg.write_text(json.dumps(config_obj, indent=2))
            step = td / "step.sh"
            step.write_text(extract_step())
            return subprocess.run(
                ["bash", "-e", str(step)],
                capture_output=True, text=True, cwd=td,
                env={
                    "PATH": "/usr/local/bin:/usr/bin:/bin",
                    "CONFIG": "cloud-environment.json",
                    "SCRIPT": script_name,
                },
            )

    def digest_of(self, config_obj):
        with tempfile.TemporaryDirectory() as td:
            cfg = pathlib.Path(td) / "c.json"
            cfg.write_text(json.dumps(config_obj))
            r = subprocess.run(
                ["node", str(SCRIPT), "--config", str(cfg), "--print-digest"],
                capture_output=True, text=True, check=True,
            )
            return r.stdout.strip()

    def test_consistent_record_passes(self):
        cfg = json.loads(json.dumps(BASE))
        cfg["environmentVariables"]["TEST_ENV_CONFIG"] = self.digest_of(cfg)
        r = self.run_step(cfg)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_stale_digest_fails(self):
        # The case this lane exists for: someone edits the domain list and forgets the
        # recorded value, leaving the file instructing the dialog to use a dead digest.
        cfg = json.loads(json.dumps(BASE))
        cfg["environmentVariables"]["TEST_ENV_CONFIG"] = self.digest_of(cfg)
        cfg["networkAccess"]["allowedDomains"].append(
            {"domain": "added-later.example", "reason": "fixture"}
        )
        r = self.run_step(cfg)
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("::error::", r.stdout)

    def test_absent_recorded_value_fails(self):
        # Absent must not be the one way to make this check unfailable.
        cfg = json.loads(json.dumps(BASE))
        cfg["environmentVariables"] = {}
        r = self.run_step(cfg)
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("does not record", r.stdout)

    def test_missing_handshake_fails(self):
        cfg = json.loads(json.dumps(BASE))
        del cfg["handshake"]
        r = self.run_step(cfg)
        self.assertEqual(r.returncode, 1, r.stdout)

    def test_structurally_invalid_record_fails(self):
        # --print-digest refuses to emit over an empty allowlist (a typo'd container key
        # once hashed zero domains and still produced a plausible digest). That refusal
        # must surface as a failure here, not as a comparison against an empty string.
        cfg = json.loads(json.dumps(BASE))
        cfg["networkAccess"] = {"allowedDomians": cfg["networkAccess"]["allowedDomains"]}
        r = self.run_step(cfg)
        self.assertEqual(r.returncode, 1, r.stdout)

    def test_missing_files_fail(self):
        with tempfile.TemporaryDirectory() as td:
            td = pathlib.Path(td)
            step = td / "step.sh"
            step.write_text(extract_step())
            r = subprocess.run(
                ["bash", "-e", str(step)],
                capture_output=True, text=True, cwd=td,
                env={
                    "PATH": "/usr/local/bin:/usr/bin:/bin",
                    "CONFIG": "nope.json",
                    "SCRIPT": "nope.mjs",
                },
            )
            self.assertEqual(r.returncode, 1)
            self.assertIn("not found", r.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
