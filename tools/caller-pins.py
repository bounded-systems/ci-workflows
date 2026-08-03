#!/usr/bin/env python3
# Which adopting repos are running a STALE copy of the shared osv-scan lane?
#
# WHY THIS EXISTS
# ---------------
# `uses: .../osv-scan.yml@<sha>` resolves the reusable workflow AT THAT COMMIT,
# including the scanner version and digest pinned inside it. So a caller's pin
# decides which scanner that repo actually runs. A caller left behind therefore
# does not just have a cosmetically old file — it is scanning with old rules, and
# every improvement to the lane (converter fixes, digest corrections, the
# `grace-expires` safety rails) reaches it only when someone re-pins it by hand.
#
# Nothing detected that. templates/ has no drift lane against its callers, which
# is how the two 2026-07-30 adopters sat four commits back unnoticed
# (ci-workflows#10), and then how the polarity INVERTED: #10 re-pinned those two,
# the fan-out landed ~44 repos on what was current that day, the template moved
# on, and the two repaired repos became the only current ones. A one-time re-pin
# fixes a day; only a standing check fixes the class.
#
# WHY `git cat-file -e` IS NOT ENOUGH — the lesson that shaped this file.
# ----------------------------------------------------------------------
# self-test already resolves template pins against real commits. That catches a
# FABRICATED sha (`@REPLACE_WITH_MERGE_SHA`, a hand-typed 40-hex). It is
# structurally blind to the failure that actually happened, twice, in both
# directions: a stale-but-VALID pin. `62990dd` is a real commit and resolves
# perfectly; it is simply old.
#
# What distinguishes staleness is ANCESTRY, not existence:
#
#     git merge-base --is-ancestor <caller-pin> <template-pin>
#
# true exactly when the caller is behind. That is the check here, and it is why
# this cannot live inside templates/ — it has to compare a caller against the
# template, which means reading other repositories.
#
# SCOPE, STATED RATHER THAN IMPLIED
# ---------------------------------
# This reports. It does not re-pin. Opening a PR per laggard needs
# contents:write + pull_requests:write across the org, which in this org means a
# NEW pinned entry in the broker's GH_APPS map (the `bounded-systems-front-desk`
# App is already installed on all repos; `front-desk-pin` is the existing
# precedent at exactly those permissions). That is a wrangler.jsonc change
# through the reviewer-gated broker-deploy lane, so it is deliberately a separate
# step from landing the measurement.
#
# Unauthenticated by default, which means PUBLIC repos only. Private repos
# (`infra`, `trellis-private`) are invisible here and are reported as such rather
# than silently omitted — an unauthenticated census that quietly skipped them
# would be its own hollow green. Pass a token to include them.
#
# No third-party imports: runner Pythons do not guarantee `requests`, the same
# constraint that already shapes deno-lock-cdx.py and check_template_pins.py.
import argparse
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request

API = "https://api.github.com"
# Caller files are read from raw.githubusercontent, NOT the API's contents
# endpoint, and that is a correctness fix rather than a preference.
#
# Unauthenticated api.github.com allows 60 requests/hour. The census makes one
# call per repo — ~90 for this org — so the first run (30860781598) sailed past
# the limit and took 23 consecutive HTTP 403s, silently truncating the census to
# whichever repos happened to be alphabetically early. Authenticating would fix
# the limit and break the census a different way: `github.token` is scoped to
# THIS repo, so it cannot read another repo's contents at all.
#
# raw.githubusercontent serves public files from a CDN, is not metered against
# that 60/hour budget, and needs no credential. The org listing stays on the API
# because it has no raw equivalent — but that is one or two calls, not ninety.
RAW = "https://raw.githubusercontent.com"
CALLER_PATH = ".github/workflows/deps.yml"

# `uses: bounded-systems/ci-workflows/.github/workflows/osv-scan.yml@<40hex>`.
# Raw text, not YAML: see the module note above.
OSV_PIN = re.compile(
    r"uses:\s*bounded-systems/ci-workflows/\.github/workflows/osv-scan\.yml@([0-9a-f]{40})"
)


def extract_pin(text):
    """The osv-scan pin in a caller file, or None if it does not call the lane.

    Returns the FIRST match. A file with two different pins is malformed rather
    than ambiguous, and `pin_count` exists so callers can say so.
    """
    if text is None:
        return None
    m = OSV_PIN.search(text)
    return m.group(1) if m else None


def pin_count(text):
    """How many osv-scan pins the file carries. Anything but 1 is worth saying."""
    return 0 if text is None else len(OSV_PIN.findall(text))


def is_ancestor(older, newer, cwd=None):
    """True when `older` is an ancestor of `newer` in the local checkout.

    Returns None when the question cannot be answered here — either sha unknown
    to this clone (shallow checkout, or a pin from a fork). None is NOT False:
    conflating "behind" with "cannot tell" is how a census reports confidence it
    does not have.
    """
    for sha in (older, newer):
        if subprocess.run(
            ["git", "cat-file", "-e", f"{sha}^{{commit}}"],
            cwd=cwd,
            capture_output=True,
        ).returncode != 0:
            return None
    return subprocess.run(
        ["git", "merge-base", "--is-ancestor", older, newer],
        cwd=cwd,
        capture_output=True,
    ).returncode == 0


def classify(caller_sha, template_sha, ancestor):
    """current | behind | ahead-or-diverged | unknown"""
    if caller_sha == template_sha:
        return "current"
    if ancestor is None:
        return "unknown"
    return "behind" if ancestor else "ahead-or-diverged"


def _get(url, token, accept="application/vnd.github+json"):
    req = urllib.request.Request(url, headers={
        "Accept": accept,
        "User-Agent": "bounded-systems-caller-pins",
        **({"Authorization": f"Bearer {token}"} if token else {}),
    })
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read(), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers or {})


def list_org_repos(org, token=None):
    """Every non-archived repo the caller can see, following Link pagination."""
    repos, url = [], f"{API}/orgs/{org}/repos?per_page=100&type=all"
    while url:
        status, body, headers = _get(url, token)
        if status != 200:
            raise SystemExit(f"listing {org} repos failed: HTTP {status} {body[:200]!r}")
        for r in json.loads(body):
            if not r.get("archived"):
                repos.append({"name": r["name"], "private": r.get("private", False)})
        url = None
        for part in headers.get("Link", "").split(","):
            if 'rel="next"' in part:
                url = part[part.find("<") + 1:part.find(">")]
    return sorted(repos, key=lambda r: r["name"])


# A cloud session's GH_TOKEN is the literal string `proxy-injected` — a sentinel,
# not a credential. The real one is injected at the egress proxy for GitHub hosts,
# so the variable is set and non-empty and cannot be presented to anything.
# Forwarding it as `Authorization: Bearer proxy-injected` makes raw 404 EVERY
# file, which reads exactly like "no repo has a caller". Caught here only because
# the empty-census guard refuses to report success on zero rows.
SENTINEL_TOKEN = "proxy-injected"


def real_token(env=None):
    """The ambient token, or None if it is absent or the session sentinel."""
    env = os.environ if env is None else env
    tok = env.get("GH_TOKEN") or env.get("GITHUB_TOKEN") or ""
    return None if (not tok or tok == SENTINEL_TOKEN) else tok


def caller_url(org, repo):
    """Where a caller file is read from. `HEAD` resolves to the default branch."""
    return f"{RAW}/{org}/{repo}/HEAD/{CALLER_PATH}"


def fetch_caller(org, repo, token=None):
    """The caller file's text, or None if the repo does not have one.

    A 404 means "not a caller" and is normal. Anything else RAISES — a
    rate-limited 403 quietly read as "no caller" would shrink the census while
    still reporting success, which is the exact hollow-green shape this file
    exists to close. Run 30860781598 is the evidence: 23 repos 403'd and the
    summary line still printed a confident-looking `callers: 43`.
    """
    status, body, _ = _get(caller_url(org, repo), token, accept="*/*")
    if status == 404:
        return None
    if status != 200:
        raise RuntimeError(f"{org}/{repo}: HTTP {status} reading {CALLER_PATH}")
    return body.decode("utf-8", "replace")


def template_pin(root):
    text = (root / "templates" / "deps.yml").read_text()
    sha = extract_pin(text)
    if not sha:
        raise SystemExit("templates/deps.yml carries no osv-scan pin — refusing to compare against nothing")
    return sha


def main(argv=None):
    ap = argparse.ArgumentParser(description="Report adopting repos whose osv-scan pin lags the template.")
    ap.add_argument("--org", default="bounded-systems")
    # A cloud session cannot enumerate the org — `GET /orgs/{org}/repos` is 403 at
    # the egress proxy ("sessions are bound to their configured repositories"),
    # which is why the census belongs in a workflow. `--repos` makes the tool
    # usable from a session anyway, for spot-checking a handful by name.
    ap.add_argument("--repos", help="comma-separated repo names; skips org enumeration")
    ap.add_argument("--repo-root", default=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    ap.add_argument("--json", action="store_true", help="emit the full report as JSON")
    ap.add_argument("--fail-on-lag", action="store_true", help="exit 1 if any caller is behind")
    args = ap.parse_args(argv)

    import pathlib
    root = pathlib.Path(args.repo_root)
    token = real_token()
    tpl = template_pin(root)

    if args.repos:
        listing = [{"name": n.strip(), "private": False} for n in args.repos.split(",") if n.strip()]
    else:
        listing = list_org_repos(args.org, token)

    rows, errors, unreadable_private = [], [], 0
    for r in listing:
        # A private repo is not on raw without a credential. Skipping it and
        # COUNTING it is the honest move: attempting it would 404 and be
        # indistinguishable from "has no caller", quietly shrinking the census.
        if r["private"] and not token:
            unreadable_private += 1
            continue
        try:
            text = fetch_caller(args.org, r["name"], token)
        except RuntimeError as e:
            errors.append(str(e))
            continue
        if text is None:
            continue
        sha = extract_pin(text)
        if sha is None:
            errors.append(f"{r['name']}: has {CALLER_PATH} but no osv-scan pin")
            continue
        n = pin_count(text)
        rows.append({
            "repo": r["name"],
            "pin": sha,
            "state": classify(sha, tpl, is_ancestor(sha, tpl, cwd=root)),
            **({"pins_found": n} if n != 1 else {}),
        })
    summary_note = f"{unreadable_private} private repo(s) were not examined" if unreadable_private else None

    behind = [r for r in rows if r["state"] == "behind"]
    summary = {
        "template": tpl,
        "callers": len(rows),
        "current": sum(1 for r in rows if r["state"] == "current"),
        "behind": len(behind),
        "unknown": sum(1 for r in rows if r["state"] == "unknown"),
        "ahead_or_diverged": sum(1 for r in rows if r["state"] == "ahead-or-diverged"),
        "authenticated": bool(token),
        "unexamined_private": unreadable_private,
        "errors": len(errors),
    }

    if args.json:
        print(json.dumps({"summary": summary, "rows": rows, "errors": errors}, indent=1))
    else:
        width = max((len(r["repo"]) for r in rows), default=4)
        for r in sorted(rows, key=lambda r: (r["state"] != "behind", r["repo"])):
            mark = {"current": "✓", "behind": "✗", "unknown": "?", "ahead-or-diverged": "!"}[r["state"]]
            print(f"{mark} {r['repo']:<{width}}  {r['pin'][:7]}  {r['state']}")
        for e in errors:
            print(f"::warning::{e}")
        if summary_note:
            print(f"::notice::unauthenticated — {summary_note}")
        print()
    # One machine-readable line, the same idiom as FDS-CLAIM-RESULT / FDS-PARITY-RESULT:
    # greppable out of a job log without parsing the table.
    print("FDS-PINS-RESULT " + json.dumps(summary, separators=(",", ":")))

    # Refuse to report success on an empty census — the hollow-green shape
    # check_template_pins.py already guards against one lane over.
    if not rows:
        print("::error::found ZERO callers — refusing to report success on an empty census")
        return 1
    if errors:
        return 1
    if behind and args.fail_on_lag:
        names = ", ".join(r["repo"] for r in behind)
        print(f"::error::{len(behind)} caller(s) lag the template ({tpl[:7]}): {names}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
