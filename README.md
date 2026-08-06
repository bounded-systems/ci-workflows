# ci-workflows

Reusable GitHub Actions workflows shared across `bounded-systems`.

**This repo is public on purpose.** Private-repo workflows and actions never resolve into
public callers, and no org setting overrides that. The same constraint already forced the
approval gate into its own public repo
([`bounded-systems/await-approval`](https://github.com/bounded-systems/await-approval)).
With ~87 public repos to serve, a shared workflow has to live somewhere public.

| workflow | what it does |
|---|---|
| `.github/workflows/osv-scan.yml` | Scans a repo's dependency lockfiles against the OSV database. Hard-fails on a known vulnerability. |
| `.github/workflows/env-check-drift.yml` | Fails when a caller's vendored `.claude/hooks/cloud-env-check.mjs` has drifted from `tools/cloud-env-check.mjs` here. |
| `.github/workflows/env-record.yml` | Fails when a caller's `.claude/cloud-environment.json` records a handshake digest that disagrees with its own contents. |

`env-check-drift` and `env-record` are complements, not alternatives: one asks whether the
**script** is canonical, the other whether the **record** is internally honest. A repo can
pass either and fail the other.

**Got a red `osv` check? → [REMEDIATION.md](./REMEDIATION.md).** A four-rung ladder —
relock, bump the parent, override, accept with an expiry — ordered by how much opinion
each embeds in the tree. It exists because ~45 repos were cleared ad hoc during the
2026-07-30 rollout and the inconsistency was itself a defect: two repos stalled as
"needs a decision" when rung 3 answered them, and adoption grace masked a CVSS 8.8.

## Relationship to `bounded-systems/.github/required-baseline.yml`

`required-baseline.yml` in the org's `.github` repo describes itself as "the enforced
security FLOOR for every repo … injected on every repo's PRs by an org ruleset (the
`workflows` rule)". **It is not injected, and it has never run.** Verified 2026-07-30:

- the only org rulesets reaching `front-desk-scheduler` are `default-branch-protection`
  (rule types `deletion`, `non_fast_forward`, `pull_request`, `required_linear_history`,
  `required_signatures`) and `protect important repos` (`repository_delete`,
  `repository_transfer`). **Neither contains a `workflows` rule.**
- `required-baseline` appears **zero times** in that repo's run history.

The likely cause is the plan: ruleset-injected required workflows are a GitHub Enterprise
feature and this org is on Free — the same class of limit that already blocked environment
required-reviewers (`infra/github-admin/README.md`). That makes the injection mechanism
unavailable rather than misconfigured.

**That is why this repo exists as a per-repo caller rather than an org injection.** Until
the plan changes, adoption has to be an explicit `uses:` in each repo. `required-baseline.yml`
should be wired up, deleted, or clearly marked inert — as written it reads like a control
protecting every repo, and it is not. Tracked in
[infra#104](https://github.com/bounded-systems/infra/issues/104).

The two also disagree on posture: `required-baseline` is deliberately report-only
(`continue-on-error: true`); this workflow hard-fails. If the baseline is ever wired up,
reconcile them rather than running both.

## Using `osv-scan`

**The standardized way: copy [`templates/deps.yml`](templates/deps.yml) byte-identical to
`.github/workflows/deps.yml` in the adopting repo.** Identical callers everywhere means
the next scanner bump is one review of one diff, applied fleet-wide by the same sed. The
template includes the weekly Tuesday rescan (one day after this repo's Monday self-test
canary, so a broken digest is caught here before the fleet rescans on it). Hand-rolled
callers are for repos that genuinely need different triggers:

```yaml
name: deps
on:
  push:
    branches: [main]
  pull_request:
  workflow_dispatch:

permissions:
  contents: read

jobs:
  osv:
    uses: bounded-systems/ci-workflows/.github/workflows/osv-scan.yml@<full-sha>  # vX.Y.Z
```

Pin the **full commit SHA**, not a tag or branch — the org's Actions policy requires it,
and it is the whole reason a shared workflow is safe to fan out this widely.

### Inputs

| input | default | notes |
|---|---|---|
| `runs-on` | `ubuntu-latest` | Runner label. |
| `scan-path` | `.` | Directory to scan, relative to the repo root. |
| `ref` | *(caller's ref)* | Set only when scanning something other than the triggering commit. |

The scanner **version and digest are not inputs** — they are a matched pair, and a caller
able to override either one could silently defeat the pin. Bumping the scanner is an edit
to `osv-scan.yml`, reviewed once, inherited by every caller.

### When something is found

The lane goes red. To accept a finding, commit an `osv-scanner.toml` beside the lockfile:

```toml
[[IgnoredVulns]]
id = "GHSA-xxxx-xxxx-xxxx"
reason = "Not reachable: we never call the affected codepath. Revisit when upstream ships a fix."
```

It is picked up automatically, and it leaves the reason in the tree as a reviewable diff
rather than quietly weakening the lane.

## Coverage — read this before assuming a green check means much

Scan targets are derived from `git ls-files` against a multi-ecosystem basename list
(npm, Cargo, Go, Python, Maven and the other ecosystems OSV-Scanner supports) and passed
as explicit `--lockfile=` args — the same list as the org's `repo-standard.yml` osv job.
The scanner's own `-r` directory walk is deliberately not used: it applies `.gitignore`
*patterns* without git's tracked-file exemption, so a repo that gitignored its own
committed lockfile scanned nothing and still reported green — hooksmith#108 shipped
sixteen advisories behind exactly that for months (fixed as .github#103; the tell in the
log is `0 Extract calls` next to a green check).

**`deno.lock` has no osv-scanner extractor**, but the lane covers its npm subset anyway
([#1](https://github.com/bounded-systems/ci-workflows/issues/1)): a v4/v5 lock already
contains the fully-resolved npm graph, so a convert step re-encodes it as a CycloneDX SBOM
(`tools/deno-lock-cdx.py`, embedded in the workflow) that the discovery step passes to the
scanner explicitly.
Concretely, on `front-desk-scheduler` that turned 0 scanned deno.lock packages into 103.

What a Deno-first repo's green check means, bucket by bucket — the scan log prints these
counts per lock:

| bucket | example | scanned? |
|---|---|---|
| npm-registry deps | `mysql2@3.13.0`, `@hono/node-server` | ✅ via the generated SBOM |
| JSR deps via npm-compat (`@jsr/*`) | `@jsr/bounded-systems__verbspec` | ❌ served from `npm.jsr.io`, not npmjs — no OSV advisory can exist under that purl, so listing them would inflate the count without adding coverage |
| JSR-native / remote deps | `jsr:@bounded-systems/verbspec` | ❌ OSV has no JSR ecosystem — nothing can scan these today |

The converter is a **pure function**: no timestamp, no random serialNumber, sorted
components, byte-identical output for identical input — enforced by golden tests
(`test/`), a heredoc↔file drift check (`test/check_embed_sync.py`), and reproducible
locally with `nix flake check`. Unsupported lock versions (v3 and older) produce a
`::warning::` and are skipped, not a red X — they were previously scanned as nothing at
all, and adoption should not force lock migrations.

A repo with nothing scannable passes explicitly — the discovery step logs "nothing
scannable, passing explicitly" and the scan step is skipped — rather than red-lining.
"Scanned nothing" and "scanned and clean" are always distinguishable in the log.

**Scans run on PR/push only.** An advisory published *after* a lock merges goes unnoticed
until the next change. Cheap fix, per caller: add a `schedule:` cron to the caller
workflow so the repo rescans weekly. (A central scanning service was considered and
rejected for now — see #1: it would add an availability dependency and a standing GitHub
credential, against the zero-standing-grants property that justified this lane.)

## Using `env-check-drift`

Copy [`templates/env-check.yml`](templates/env-check.yml) to `.github/workflows/env-check.yml`
in the adopting repo, and pin the full SHA. Same standardization argument as `deps.yml`.

`cloud-env-check.mjs` reconciles the hand-configured claude.ai/code environment dialog
against a repo's checked-in record of it, and `--verify-domains` **probes** the allowlist
rather than trusting the digest. It is repo-agnostic: everything repo-specific lives in a
`handshake` block in `.claude/cloud-environment.json`.

```json
"handshake": { "variable": "INFRA_ENV_CONFIG", "prefix": "INFRA_" }
```

**Adoption is four things, not the two the script's header claims** — the script, the
config, an invocation from a SessionStart hook, and the variable in the dialog. Steps 3
and 4 live outside both files, and without them nothing runs. This lane covers step 1 only.

### Why it is vendored rather than published

Tempting to put it on JSR next to `@bounded-systems/guest-room`. It is the wrong shape: a
SessionStart hook runs **before dependencies are installed**, so importing it would fetch
it over the network using the very allowlist it exists to validate. If the allowlist is
broken the check cannot run, precisely when you need it. (Same reason the script imports
nothing but node stdlib and shells out to `curl` — `curl` honours `HTTPS_PROXY` and the
proxy CA bundle without the script knowing either exists.)

So every adopter keeps a copy on disk, and the cost of that is drift. This lane makes the
drift loud — the same trade `tools/deno-lock-cdx.py` already makes against its embedded
twin, and the pattern infra's `proofs/check-sync.mjs` uses.

### Why a digest, not a fetch

A reusable workflow's steps run in the **caller's** checkout, so `tools/` is not on disk
there and the canonical bytes cannot be diffed against directly. Fetching them would put a
network dependency inside a check about network configuration — the same circularity the
vendoring exists to avoid. The pin is `CANONICAL_SHA256` in `env-check-drift.yml`, and
`test/check_env_check_digest.py` fails if it disagrees with `tools/cloud-env-check.mjs`, so
a half-done bump reddens **this** repo before any caller.

Like the scanner digest, it is **not a caller input**: a caller able to override it could
declare its own drifted copy canonical and silently defeat the check.

### Bumping the canonical script

1. Edit `tools/cloud-env-check.mjs`
2. Update `CANONICAL_SHA256` in `.github/workflows/env-check-drift.yml` (`sha256sum tools/cloud-env-check.mjs`)
3. Merge — `self-test` proves the two agree
4. Re-vendor into each adopting repo and bump its caller pin

Steps 1–3 are one review. Step 4 is per-repo and is what the lane makes visible: a repo
that skips it goes red on its next relevant PR instead of drifting unnoticed.

### Bumping the shared osv-scan lane

The same shape, with one step that exists because skipping it is what
[#10](https://github.com/bounded-systems/ci-workflows/issues/10) is about:

1. Edit `.github/workflows/osv-scan.yml`
2. Merge, and re-pin `templates/deps.yml` to the merge commit — `release-tag.yml`
   mints the version tag on that push automatically
3. **Let the callers converge, then verify.** Dependabot (`templates/dependabot.yml`,
   vendored per repo as `.github/dependabot.yml`) opens each caller's re-pin PR on its
   weekly cycle; a human merges. The Monday `caller-pins.yml` census proves the fleet
   actually converged.

The tag in step 2 is load-bearing, not ceremony: **Dependabot resolves a SHA-pinned
`uses:` via the referenced repo's tags, so an untagged repo is invisible to it.**
Measured, not assumed — guest-room ran this exact Dependabot config weekly since June,
and its refreshed group PR (guest-room#61) bumped `checkout`/`codeql`/`scorecard` pins
across three files while leaving `deps.yml`'s osv-scan pin untouched at `8b7d8a8`,
three template moves behind. Same engine, same config; the only difference was tags.

Step 3 matters because `uses: …@<sha>` resolves the reusable workflow *at that commit*:
a caller's pin decides which scanner that repo actually runs, a lane improvement that
stops at step 2 is merged and deployed to nobody, and — unlike the canonical-script
gate above — **nothing makes a stale caller go red on its own.** The 2026-08-03 census
measured 43 of 58 callers behind for exactly this reason (ci-workflows#10).

The division of labour is deliberate, and it is the OpenTofu shape: the template is the
**desired state**, the census is the **plan** (an ancestry diff — `merge-base
--is-ancestor` — because a stale pin *is* a real commit, so existence checks cannot see
it; `62990dd` resolves perfectly and is four behind), Dependabot is the **apply**, and
merging stays human. Once the fleet reads current, flip `caller-pins`' `fail-on-lag`
to `true`: from then on the plan must be empty, and a caller that lags a week reds the
Monday lane instead of drifting silently.

Why Dependabot rather than a broker-credentialed re-pin bot: the engine is
GitHub-maintained (nothing bespoke to keep working); a custom actor would need
org-wide `contents:write` *plus* the `workflows` permission — GitHub rejects
workflow-file pushes without it — minted from an entry that would make this repo's
`main` a lever over every repo's contents; and Dependabot also covers what the census
cannot see: consumers that call the lane from inside a combined workflow (infra's
`_infra-test.yml`) and every other action pin going stale the same way.

**Two copies, currently in step.** `infra` and `front-desk-scheduler` both carry
`c530b86a…`, byte-identical to canonical as of adoption — so this gate was introduced
green and only ever fires on real future divergence.

### What it does not do

Open a PR to fix the drift. It fails, the same way `check_embed_sync.py` and
`schema-drift.yml` do, and that has been enough. Nor does it fix the dialog — the dialog is
UI-configured and outside any session's control.

## The scanner binary, and why it is pinned by digest

OSV-Scanner runs as a **pinned release binary**, not via `google/osv-scanner-action`. A
third-party action can invoke nested actions **by tag** — the proofs lane hit exactly this
when `lean-action` reached for `actions/cache/restore@v5` — and SHA-pinning the parent
cannot exempt its children. The org's full-SHA-pin policy rejects that. A release binary
has no children.

Current pin:

| | |
|---|---|
| version | `v2.4.0` |
| asset | `osv-scanner_linux_amd64` |
| sha256 | `15314940c10d26af9c6649f150b8a47c1262e8fc7e17b1d1029b0e479e8ed8a0` |

### Provenance

infra#104 flagged that the original digest was captured inside a Claude Code session whose
egress runs through a TLS-intercepting proxy — *"pinned to what we saw"*, not a vendor
attestation — and asked for it to be re-derived before becoming an org-wide control.

Upstream publishes no `checksums.txt`, but it does publish a **SLSA provenance bundle**,
which is stronger than a checksums file. Verified 2026-07-30:

- the bundle's DSSE signature **verifies** against its embedded Fulcio certificate;
- the signed in-toto statement lists the digest above as the subject for
  `osv-scanner_linux_amd64`;
- the signing identity is the SLSA generator, not an ad-hoc key:

| field | value |
|---|---|
| SAN | `slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.1.0` |
| OIDC issuer | `https://token.actions.githubusercontent.com` |
| source | `github.com/google/osv-scanner` @ `refs/tags/v2.4.0` |
| commit | `b56b5191101d5f27d4787d5583d8d01e9518a7af` |
| build run | [`google/osv-scanner` run 27762425209](https://github.com/google/osv-scanner/actions/runs/27762425209) |

**Residual gap, stated plainly:** the certificate was not chained to the Sigstore root
out-of-band, and Rekor was unreachable from the verifying session (egress policy), so the
transparency-log inclusion proof was **not** checked. A sufficiently capable interceptor
holding a forged Fulcio-chained certificate could still have produced what was observed —
a far higher bar than swapping a binary, but not zero.

Reproduce anywhere with open egress:

```sh
gh attestation verify --owner google \
  --bundle multiple.intoto.jsonl osv-scanner_linux_amd64
```

Or without `gh`, checking the signature and the subject directly:

```sh
V=v2.4.0
base=https://github.com/google/osv-scanner/releases/download/$V
curl -sSfLO $base/osv-scanner_linux_amd64
curl -sSfLO $base/multiple.intoto.jsonl
sha256sum osv-scanner_linux_amd64

python3 - <<'PY'
import json, base64
b = json.loads(open("multiple.intoto.jsonl").read().strip())
env = b["dsseEnvelope"]
open("cert.der","wb").write(base64.b64decode(b["verificationMaterial"]["certificate"]["rawBytes"]))
payload, pt = base64.b64decode(env["payload"]), env["payloadType"].encode()
open("pae.bin","wb").write(
    b"DSSEv1 " + str(len(pt)).encode() + b" " + pt + b" "
    + str(len(payload)).encode() + b" " + payload)
open("sig.der","wb").write(base64.b64decode(env["signatures"][0]["sig"]))
for s in json.loads(payload)["subject"]:
    print(s["digest"]["sha256"], s["name"])
PY

openssl x509 -in cert.der -inform DER -out cert.pem
openssl x509 -in cert.pem -noout -pubkey > pub.pem
openssl dgst -sha256 -verify pub.pem -signature sig.der pae.bin   # -> Verified OK
openssl x509 -in cert.pem -noout -text | grep -A2 "Subject Alternative Name"
```

Re-run this when bumping the version, and update both the digest and the identity table.
A wrong-but-stable digest fails loudly; an unpinned binary changes silently.
