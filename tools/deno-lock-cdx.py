#!/usr/bin/env python3
# deno.lock (v4/v5) -> CycloneDX 1.5 SBOM, npm-registry subset only.
#
# This is a PURE FUNCTION with a file interface: the same deno.lock bytes must
# produce byte-identical SBOM output, forever, on any machine. That is why there
# is no timestamp, no random serialNumber (both optional in CycloneDX; the usual
# UUID default is exactly the nondeterminism this refuses), components are
# sorted, and json.dumps uses sort_keys with fixed indentation. The golden tests
# in test/ enforce byte-equality; do not add anything environment-dependent.
#
# Three buckets, reported honestly (osv-scanner reads the SBOM this writes):
#   npm-registry deps        -> included: OSV's npm ecosystem can match them
#   @jsr/* npm-compat deps   -> EXCLUDED: served from npm.jsr.io, not npmjs.
#                               No OSV advisory can exist under that purl, so
#                               including them would inflate the "scanned" count
#                               without adding coverage.
#   jsr-native deps          -> EXCLUDED: OSV has no JSR ecosystem.
# The one-line summary this prints per lock is the lane's honesty about that.
#
# stdlib only, deliberately: nothing to install, nothing to SHA-pin beyond what
# the lane already pins, and `nix flake check` runs the identical tests locally.
import json
import re
import sys
from urllib.parse import quote

# npm/jsr section keys look like "name@version" with an optional "_peer@ver..."
# suffix for peer-dependency variants. Names may be scoped (@scope/pkg) and may
# contain "__" (JSR's npm-compat mangling); versions are semver, which never
# contains "_". The name cannot contain "@" after its optional leading one.
KEY = re.compile(r"^(@?[^@]+)@([^_]+)(?:_.*)?$")


def parse_key(key):
    m = KEY.match(key)
    if not m:
        raise ValueError(f"unparseable lock key: {key!r}")
    return m.group(1), m.group(2)


def purl(name, version):
    # purl spec: '@' in scope and any '+' in version must be percent-encoded;
    # the '/' between scope and name stays literal.
    path = "/".join(quote(seg, safe="") for seg in name.split("/"))
    return f"pkg:npm/{path}@{quote(version, safe='')}"


def convert(lock):
    version = str(lock.get("version", ""))
    if version not in ("4", "5"):
        return None, None, version
    covered = []
    jsr_compat = 0
    seen = set()
    for key in lock.get("npm", {}) or {}:
        name, ver = parse_key(key)
        if name.startswith("@jsr/"):
            jsr_compat += 1
            continue
        if (name, ver) in seen:  # peer-variant keys collapse to one component
            continue
        seen.add((name, ver))
        covered.append((name, ver))
    covered.sort()
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "components": [
            {
                "bom-ref": purl(n, v),
                "name": n,
                "purl": purl(n, v),
                "type": "library",
                "version": v,
            }
            for n, v in covered
        ],
    }
    counts = {
        "npm_registry": len(covered),
        "jsr_via_npm_compat": jsr_compat,
        "jsr_native": len(lock.get("jsr", {}) or {}),
    }
    return sbom, counts, version


def main(argv):
    if len(argv) != 3:
        print("usage: deno-lock-cdx.py <deno.lock> <out.cdx.json>", file=sys.stderr)
        return 2
    lock_path, out_path = argv[1], argv[2]
    with open(lock_path) as f:
        lock = json.load(f)
    sbom, counts, version = convert(lock)
    if sbom is None:
        # Visible on the run summary, deliberately non-fatal: an old-format lock
        # was previously scanned as nothing at all, and turning that into a hard
        # red would make adoption force lock migrations. Loud, not blocking.
        print(
            f"::warning::{lock_path}: unsupported deno.lock version {version!r} "
            "(expected 4 or 5) - not converted, npm subset NOT scanned"
        )
        return 0
    summary = (
        f"{lock_path}: npm-registry={counts['npm_registry']} (scanned), "
        f"jsr-via-npm-compat={counts['jsr_via_npm_compat']}, "
        f"jsr-native={counts['jsr_native']} (NOT scanned - no OSV ecosystem)"
    )
    if counts["npm_registry"] == 0:
        print(summary + " -- nothing scannable, no SBOM written")
        return 0
    with open(out_path, "w") as f:
        f.write(json.dumps(sbom, indent=2, sort_keys=True) + "\n")
    print(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
