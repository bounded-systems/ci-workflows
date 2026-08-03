#!/usr/bin/env python3
# Unit tests for tools/caller-pins.py — the PURE parts only: pin extraction and
# classification. No network, no git, so this runs identically under `nix flake
# check` (store path, no .git, no network) and under self-test.
#
# The property worth pinning is the one the reconciler exists for: a stale pin is
# a VALID commit, so "resolves" and "current" are different questions and the
# classifier must never collapse them. Equally, `unknown` must never be reported
# as `behind` — a census that guesses is worse than one that abstains, because a
# guess produces a re-pin PR against a repo nobody measured.
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import importlib.util

spec = importlib.util.spec_from_file_location("caller_pins", ROOT / "tools" / "caller-pins.py")
caller_pins = importlib.util.module_from_spec(spec)
spec.loader.exec_module(caller_pins)

TEMPLATE = "162accbbcfdfd12c146c44f23770e6a6bb9abb1c"
STALE = "62990dd15f1b0deba21e597bebd1512970544c15"
OLDER = "8b7d8a8d3fbf43a4a97b47006ae40dfe32012b85"

CALLER = """name: deps
jobs:
  osv:
    uses: bounded-systems/ci-workflows/.github/workflows/osv-scan.yml@{sha} # main
"""


class TestExtract(unittest.TestCase):
    def test_finds_pin(self):
        self.assertEqual(caller_pins.extract_pin(CALLER.format(sha=STALE)), STALE)

    def test_trailing_comment_is_not_part_of_the_sha(self):
        # The `# main` provenance note sits right after the sha; a greedy pattern
        # would swallow it and produce a 40-hex that is not the pin.
        self.assertEqual(len(caller_pins.extract_pin(CALLER.format(sha=TEMPLATE))), 40)

    def test_no_pin_when_not_a_caller(self):
        self.assertIsNone(caller_pins.extract_pin("name: something-else\njobs: {}\n"))

    def test_none_input(self):
        self.assertIsNone(caller_pins.extract_pin(None))
        self.assertEqual(caller_pins.pin_count(None), 0)

    def test_a_branch_ref_is_not_a_pin(self):
        # `@main` must not read as pinned — that is the shape the org's whole
        # SHA-pin policy refuses, and reporting it as a version would hide it.
        floating = CALLER.replace("@{sha}", "@main").format(sha="")
        self.assertIsNone(caller_pins.extract_pin(floating))

    def test_short_sha_is_not_a_pin(self):
        self.assertIsNone(caller_pins.extract_pin(CALLER.format(sha=STALE[:7])))

    def test_other_workflows_are_ignored(self):
        other = "    uses: bounded-systems/ci-workflows/.github/workflows/env-check.yml@" + STALE + "\n"
        self.assertIsNone(caller_pins.extract_pin(other))

    def test_counts_duplicates(self):
        doubled = CALLER.format(sha=STALE) + CALLER.format(sha=OLDER)
        self.assertEqual(caller_pins.pin_count(doubled), 2)


class TestClassify(unittest.TestCase):
    def test_equal_is_current(self):
        self.assertEqual(caller_pins.classify(TEMPLATE, TEMPLATE, None), "current")

    def test_equal_wins_before_ancestry_is_consulted(self):
        # An identical pin is current whatever git says, so a shallow checkout
        # cannot turn the happy path into "unknown".
        self.assertEqual(caller_pins.classify(TEMPLATE, TEMPLATE, False), "current")

    def test_ancestor_is_behind(self):
        self.assertEqual(caller_pins.classify(STALE, TEMPLATE, True), "behind")

    def test_unresolvable_is_unknown_not_behind(self):
        # The load-bearing one: abstain rather than guess.
        self.assertEqual(caller_pins.classify(STALE, TEMPLATE, None), "unknown")

    def test_non_ancestor_is_not_behind(self):
        self.assertEqual(caller_pins.classify(STALE, TEMPLATE, False), "ahead-or-diverged")


class TestCallerUrl(unittest.TestCase):
    def test_reads_from_raw_not_the_api(self):
        # Load-bearing: the API's contents endpoint is capped at 60 req/hour
        # unauthenticated, and the census makes one call per repo (~90). Run
        # 30860781598 hit that ceiling and took 23 straight 403s. raw is a CDN,
        # unmetered against that budget, and needs no credential.
        url = caller_pins.caller_url("bounded-systems", "brand")
        self.assertTrue(url.startswith("https://raw.githubusercontent.com/"))
        self.assertNotIn("api.github.com", url)

    def test_points_at_the_default_branch_and_the_caller_path(self):
        url = caller_pins.caller_url("bounded-systems", "brand")
        self.assertEqual(
            url, "https://raw.githubusercontent.com/bounded-systems/brand/HEAD/.github/workflows/deps.yml"
        )


class TestRealToken(unittest.TestCase):
    def test_sentinel_is_not_a_credential(self):
        # A cloud session's GH_TOKEN is the literal string `proxy-injected`.
        # Forwarding it as a Bearer makes raw 404 every file, which reads exactly
        # like "no repo has a caller" — a silently empty census.
        self.assertIsNone(caller_pins.real_token({"GH_TOKEN": "proxy-injected"}))

    def test_empty_is_none(self):
        self.assertIsNone(caller_pins.real_token({"GH_TOKEN": ""}))
        self.assertIsNone(caller_pins.real_token({}))

    def test_a_real_token_passes_through(self):
        self.assertEqual(caller_pins.real_token({"GH_TOKEN": "ghs_abc123"}), "ghs_abc123")

    def test_github_token_is_a_fallback(self):
        self.assertEqual(caller_pins.real_token({"GITHUB_TOKEN": "ghs_xyz"}), "ghs_xyz")


class TestTemplateIsItsOwnFixture(unittest.TestCase):
    def test_the_real_template_carries_a_pin(self):
        # Guards the comparison basis itself: if templates/deps.yml ever stops
        # carrying an osv-scan pin, every caller would compare against nothing
        # and the census would read as uniformly diverged.
        text = (ROOT / "templates" / "deps.yml").read_text()
        self.assertIsNotNone(caller_pins.extract_pin(text))
        self.assertEqual(caller_pins.pin_count(text), 1)


if __name__ == "__main__":
    unittest.main()
