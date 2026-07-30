#!/usr/bin/env python3
# Every `uses:` in templates/ must be pinned to a full 40-hex commit SHA, and must
# carry a trailing `# <ref>` comment recording what that SHA was at the time.
#
# WHY THIS EXISTS — the fourth hollow green (infra docs/cloud-sessions.md).
# self-test once passed on a commit whose reusable-workflow pin was a NONEXISTENT
# SHA. Nothing in CI resolved template pins, so `@REPLACE_WITH_MERGE_SHA` and a
# fabricated 40-hex string were equally invisible. A template is copied verbatim
# into adopting repos, so a bad pin here does not fail here — it fails in every
# repo that adopts it, at a time nobody connects to this commit.
#
# WHAT THIS CHECKS, AND WHAT IT DELIBERATELY DOES NOT.
# This script is SHAPE ONLY: 40 lowercase hex, no tag/branch refs, no placeholder
# text, provenance comment present. It does NOT check that the SHA names a real
# commit — that needs git history, and this script must run under BOTH runners
# (see flake.nix: "test/ should have no file that neither runner executes"). Under
# `nix flake check` the tree is a store path with no .git and no network, so
# resolution is impossible here by construction.
#
# Resolution is the `template-pins` job in self-test.yml, which checks out with
# fetch-depth: 0 and runs `git cat-file -e`. The two are complements, not
# duplicates, and BOTH are needed:
#
#   @main                        → caught here (shape), invisible to resolution
#   @REPLACE_WITH_MERGE_SHA      → caught here (shape), invisible to resolution
#   a fabricated but well-formed → invisible here, caught by resolution
#
# Extraction is raw-text, no YAML library: runner Pythons do not guarantee PyYAML,
# and the same constraint already shapes check_env_check_digest.py.
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
TEMPLATES = ROOT / "templates"

# `uses: <owner>/<repo>/<path>@<ref>` with an optional trailing `# comment`.
USES = re.compile(r"^\s*uses:\s*(?P<slug>[^@\s]+)@(?P<ref>\S+)(?:\s+#\s*(?P<note>.*?))?\s*$")
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")


def main():
    if not TEMPLATES.is_dir():
        sys.exit(f"no templates/ directory at {TEMPLATES}")

    files = sorted(TEMPLATES.glob("*.yml"))
    if not files:
        sys.exit(f"no *.yml under {TEMPLATES} — this check would silently pass on nothing")

    problems = []
    checked = 0

    for path in files:
        for lineno, line in enumerate(path.read_text().splitlines(), 1):
            m = USES.match(line)
            if not m:
                continue
            checked += 1
            where = f"{path.name}:{lineno}"
            ref, note = m.group("ref"), m.group("note")

            if not FULL_SHA.match(ref):
                # Covers @main, @v4, @REPLACE_WITH_MERGE_SHA, and abbreviated SHAs.
                # Abbreviations matter beyond style: expanding one by hand is exactly
                # how a fabricated pin gets introduced (docs/cloud-sessions.md).
                problems.append(
                    f"{where}: `{m.group('slug')}` is pinned to `{ref}`, "
                    "which is not a full 40-hex commit SHA"
                )
                continue

            if not note:
                # The org convention is `@<sha> # <ref>` so a reviewer can tell an
                # intentional bump from a drifted one. A bare SHA reads identically
                # whether it is current or three months stale.
                problems.append(
                    f"{where}: `{m.group('slug')}` is SHA-pinned but has no trailing "
                    "`# <ref>` comment recording what the SHA was"
                )

    if not checked:
        # A check that verifies nothing must never report green — the whole point of
        # this file. templates/*.yml existing with no `uses:` line at all means either
        # the regex stopped matching the format or the templates lost their callers;
        # both are bugs, and both would otherwise pass silently.
        sys.exit(
            f"found {len(files)} template file(s) but ZERO `uses:` pins — "
            "refusing to report success on an empty check"
        )

    if problems:
        sys.exit(
            "template pin problems:\n\n  "
            + "\n  ".join(problems)
            + "\n\nEvery `uses:` in templates/ is copied verbatim into adopting repos, so a\n"
            "bad pin fails there rather than here. Derive SHAs with `git rev-parse`,\n"
            "never by hand (infra docs/cloud-sessions.md: 'Never hand-type a SHA').\n\n"
            "Note this is a SHAPE check only — that these SHAs name real commits is\n"
            "the `template-pins` job in self-test.yml."
        )

    names = ", ".join(p.name for p in files)
    print(f"{checked} template pin(s) well-formed across {len(files)} file(s): {names}")


if __name__ == "__main__":
    main()
