# Remediation ladder

How to clear a finding from the shared `osv-scan` lane. **Start at rung 1. Stop at the
first rung that works. Never skip down.**

This exists because the 2026-07-30 fleet rollout cleared ~45 repos and each one got
whatever the session in front of it thought of — fresh resolve here, parent bump there,
`npm audit fix` elsewhere, and two repos stalled on "needs a decision" that had a
perfectly good answer at rung 3. That inconsistency is itself a vulnerability: it is how
adoption grace ended up masking a CVSS 8.8 on `site` behind a green check
([#8](https://github.com/bounded-systems/ci-workflows/issues/8)).

The ladder is ordered by how much opinion each rung embeds in the tree. Lower rungs
change less and rot less.

---

## Before you start: read the scanner's own table

The lane prints one row per finding with a **`FIXED VERSION`** column. That column is the
answer to "what do I bump to". Read it.

Do not substitute another tool's verdict. `npm audit` reported *"found 0 vulnerabilities"*
on a `brand` tree the lane was failing on an 8.8 — different database, different
resolution, no obligation to agree. The lane gates on OSV, so OSV is what you check.

To check a specific version directly (`api.osv.dev` is on the session allowlist):

```sh
curl -s -X POST https://api.osv.dev/v1/query \
  -d '{"package":{"name":"brace-expansion","ecosystem":"npm"},"version":"2.1.4"}' \
| jq -r '.vulns[] | .id, (.affected[].ranges[]?.events[] | select(.fixed) | "  fixed: \(.fixed)")'
```

Note that one package can carry **several advisories with different fix lines**.
`brace-expansion` 2.1.1 has both GHSA-3jxr-9vmj-r5cp (fixed in **2.1.2**, reachable on
the 2.x line) and GHSA-mh99-v99m-4gvg (fixed in **5.0.8**, no 2.x fix). Bumping to 2.1.4
clears one and leaves the other. Check per advisory, not per package.

---

## Rung 1 — relock within declared ranges

Re-resolve without touching any manifest.

```sh
npm update <pkg>          # or: rm package-lock.json && npm install
bun update <pkg>          # or: rm bun.lock && bun install
deno outdated --update    # or: rm deno.lock && deno install
cargo update -p <pkg>
```

Embeds no opinion — the manifest already permits the fixed version, the resolver just
hadn't taken it.

**The gotcha that cost the rollout real time:** `npm update` / `bun update` /
`deno install` honour existing lock entries that still satisfy their ranges, so a
stale-but-valid entry does not move. If the targeted update reports "already up to date"
while the scanner still reports the finding, **delete the lockfile and resolve from
scratch.** That is what actually cleared `prx` and `verbspec-mcp`.

Run the repo's tests afterwards. A lockfile diff that fixes no advisory is noise — revert
it rather than committing churn.

---

## Rung 2 — bump the direct parent

When the vulnerable package is transitive and a newer parent admits the fix.

Find the parent, check whether a newer release widened its range, bump it in the
manifest, relock.

Precedent: `front-desk-scheduler` was stuck on `@hono/node-server` 1.19.14 until
`@modelcontextprotocol/sdk` 1.30.0 widened its range to `^1.19.9 || ^2.0.5` — which
upstream did for exactly this reason. `brand` is the compressed case: `style-dictionary`
was its only devDependency, so one major bump carried `minimatch` and `brace-expansion`
with it and cleared both findings at once.

Worth checking whether a parent bump clears *several* rows before treating them as
separate problems.

---

## Rung 3 — force the version with an override

When the fix exists and is published, but a parent pins below it and no newer parent
helps. **This is the rung the rollout kept skipping, and it is usually right.**

```jsonc
// package.json (npm)
"overrides": {
  // GHSA-mh99-v99m-4gvg (7.5) — parent minimatch@10 pins <5.0.8.
  // Remove when minimatch widens its range.
  "brace-expansion": "^5.0.8"
}
```

```jsonc
// package.json (bun / yarn)
"resolutions": { "brace-expansion": "^5.0.8" }
```

For Deno, promote it to a **direct** import in `deno.json` so the resolver has no room to
keep a stale transitive entry:

```jsonc
"imports": { "brace-expansion": "npm:brace-expansion@^5.0.8" }
```

Every override carries a comment naming **the advisory** and **the condition for removal**.
It is a manifest change, so it is reviewed like any other diff, and it self-clears the
moment the parent catches up.

**Always run the full test suite after an override.** You are forcing a version past a
constraint its parent declared, which is exactly the situation semver ranges exist to
prevent. If tests fail, that is real information — go to rung 4 rather than fighting it.

---

## Rung 4 — accept, with a reason and an expiry

Only when no fix exists, or rung 3 breaks the build. **Never as a shortcut past rungs 1–3.**

```toml
# osv-scanner.toml, next to the lockfile
[[IgnoredVulns]]
id = "GHSA-mh99-v99m-4gvg"
ignoreUntil = 2026-10-31
reason = "No fix on the 2.x line (fixed in 5.0.8, three majors up). Pinned by ts-morph@^23 via minimatch@9. Revisit when the AST migration lands — tracked in <issue>."
```

**`ignoreUntil` is mandatory, and it is not decoration.** Verified against osv-scanner
2.4.0: a future date filters the finding and the scan exits 0; **once the date passes the
finding returns and the scan exits 1**, with the config reported as having "unused
ignores". The tool fails closed on its own, so an acceptance genuinely expires rather than
becoming permanent by neglect.

An acceptance without an expiry is
[`required-baseline.yml`](https://github.com/bounded-systems/infra/issues/135) again: a
control that looks like protection and is not. Pick a date you would actually defend, and
name what has to happen before it.

`reason` is read by whoever hits this next. "Not exploitable" is not a reason; say why.

---

## Never on the ladder

- **Leaving `report-only: true` standing.** It is *adoption* grace — it makes a repo
  instrumented, not fixed. It downgrades findings to a warning, which is a green check
  gating nothing. If a repo needs it, give it `grace-expires` (see below) so it cannot
  quietly become permanent.
- **Hand-editing a lockfile.** It breaks the next resolve and is worse than a visible
  finding. `static-mcp` tried it and correctly reverted.
- **Trusting a second tool's opinion** about a finding the lane raised. See above.
- **Widening `scan-path` or dropping files from the scan** to make a row disappear.

---

## Adoption grace, and its expiry

`report-only: true` exists so a repo carrying pre-existing advisories can adopt the lane
immediately — instrumented and visible — instead of adoption and remediation being one
blocking task. It was always meant to be temporary, and for a while nothing enforced that.

Now it takes a date:

```yaml
uses: bounded-systems/ci-workflows/.github/workflows/osv-scan.yml@<sha>
with:
  report-only: true
  grace-expires: "2026-09-30"   # findings hard-fail from this date
```

- **No `grace-expires`** — the lane warns that the grace is unbounded. Allowed, so
  adoption is never blocked, but it says so on every run.
- **Date in the future** — findings warn, and the run states how long is left.
- **Date passed** — findings **fail hard**, exactly as if grace were absent.
- **Malformed date** — fails closed. A typo must not buy unlimited grace.

Same fail-closed-on-expiry shape as `ignoreUntil`, deliberately: one temporal contract
across both mechanisms.

A tool or network failure still fails hard in every mode. Grace downgrades *vulnerability
findings* and nothing else — a lane that could not run must never report green.

---

## When you are done

1. The lane is green at **hard-fail** — no `report-only`.
2. Any `osv-scanner.toml` entry has a `reason` and an `ignoreUntil`.
3. The repo's own tests pass.

Log non-obvious outcomes on [#8](https://github.com/bounded-systems/ci-workflows/issues/8)
so the next repo with the same shape does not re-derive it.

---

## The structural fix

Rungs 3 and 4 both exist because the org does not control what enters its dependency
graph — every build trusts npmjs and jsr.io at fetch time, unauthenticated. A registry
that refuses to serve a known-vulnerable version makes rung 3 unnecessary and rung 4 rare:
it is this ladder applied once at the registry instead of repeatedly per repo. That is
[infra#141](https://github.com/bounded-systems/infra/issues/141), and every repo that
lands on rung 3 or 4 is evidence for it — say so on the issue when you get there.
