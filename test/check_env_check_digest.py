#!/usr/bin/env python3
# The canonical cloud-env-check.mjs is named twice on purpose: as the file
# tools/cloud-env-check.mjs, and as the CANONICAL_SHA256 constant inside
# .github/workflows/env-check-drift.yml (a reusable workflow's steps run in the
# CALLER's checkout, so tools/ is not on disk there and the digest is the only
# thing that travels). Two statements of one fact is a drift bug waiting to
# happen — this check makes the drift a red X here instead of a false green on
# every adopting repo. Same pattern as check_embed_sync.py and infra's
# proofs/check-sync.mjs.
#
# Failure mode this prevents, concretely: bump tools/cloud-env-check.mjs, forget
# the constant, and every caller keeps validating against the OLD digest — so
# the repos that correctly re-vendored the new script go red, and the ones that
# did nothing stay green. Exactly backwards.
#
# Extraction is done on raw file text, no YAML library needed (runner Pythons
# don't guarantee PyYAML): the constant is the sole `CANONICAL_SHA256:` key.
import hashlib
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "env-check-drift.yml"
TOOL = ROOT / "tools" / "cloud-env-check.mjs"

PIN = re.compile(r"^\s*CANONICAL_SHA256:\s*([0-9a-f]{64})\s*$", re.MULTILINE)


def main():
    pins = PIN.findall(WORKFLOW.read_text())
    if len(pins) != 1:
        sys.exit(
            f"expected exactly one CANONICAL_SHA256 pin in {WORKFLOW.name}, "
            f"found {len(pins)}"
        )
    declared = pins[0]

    actual = hashlib.sha256(TOOL.read_bytes()).hexdigest()
    if declared != actual:
        sys.exit(
            f"CANONICAL_SHA256 in {WORKFLOW.name} does not match tools/{TOOL.name}:\n"
            f"  workflow declares {declared}\n"
            f"  file hashes to    {actual}\n\n"
            "Bump the two together. If you edited the script, put the new digest in\n"
            "the workflow; if you edited the workflow, make sure the script matches."
        )

    print(f"CANONICAL_SHA256 matches tools/{TOOL.name} ({actual}, {TOOL.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
