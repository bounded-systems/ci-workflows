#!/usr/bin/env python3
# The converter exists twice on purpose: embedded in osv-scan.yml (a reusable
# workflow's steps run in the CALLER's checkout, so tools/ is not on disk there)
# and as tools/deno-lock-cdx.py (so tests can import and golden-check it). Two
# copies of one definition is a drift bug waiting to happen — this check makes
# the drift a red X instead. Same pattern as infra's proofs/check-sync.mjs.
#
# Extraction is done on the raw file text, no YAML library needed (runner
# Pythons don't guarantee PyYAML): the heredoc body is every line between the
# <<'PY' marker and the terminator line whose stripped content is exactly PY,
# dedented by the terminator's indent. Empty lines carry no indent in YAML
# block scalars, so they pass through as-is.
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "osv-scan.yml"
TOOL = ROOT / "tools" / "deno-lock-cdx.py"


def extract_heredoc(text):
    lines = text.split("\n")
    starts = [i for i, l in enumerate(lines) if l.rstrip().endswith("<<'PY'")]
    if len(starts) != 1:
        sys.exit(f"expected exactly one <<'PY' heredoc in {WORKFLOW}, found {len(starts)}")
    body = []
    for l in lines[starts[0] + 1:]:
        if l.strip() == "PY":
            indent = len(l) - len(l.lstrip())
            return "".join(
                (x[indent:] if len(x) > indent else "") + "\n" for x in body
            ), indent
        body.append(l)
    sys.exit("unterminated heredoc: no line with content 'PY' found")


def main():
    embedded, indent = extract_heredoc(WORKFLOW.read_text())
    tool = TOOL.read_text()
    if embedded != tool:
        import difflib

        diff = "".join(
            difflib.unified_diff(
                tool.splitlines(keepends=True),
                embedded.splitlines(keepends=True),
                fromfile="tools/deno-lock-cdx.py",
                tofile="osv-scan.yml (embedded)",
            )
        )
        sys.exit(
            "embedded converter has drifted from tools/deno-lock-cdx.py — edit the\n"
            "tools file and re-embed (indent every non-empty line by "
            f"{indent} spaces):\n\n{diff}"
        )
    print(f"embedded copy matches tools/deno-lock-cdx.py ({len(tool)} bytes)")


if __name__ == "__main__":
    main()
