# rules_osv

Bazel rules for [osv-scanner](https://github.com/google/osv-scanner), the dependency vulnerability scanner for [OSV.dev](https://osv.dev). `osv_scan_test` scans lockfiles for dependencies with known vulnerabilities, **offline**, against a pinned snapshot of the OSV database, so a commit's result is reproducible and the test never calls the OSV API.

- **`osv_scan_test`**: a test that fails if `lockfiles` (pnpm-lock.yaml, package-lock.json, go.mod, Cargo.lock, requirements.txt, ...) name a package version with a known vulnerability.
  - Findings can be accepted in an ignore file, but every entry needs a **reason** and an **expiry**. An expired entry fails the test, naming it.
  - The output names the database snapshot, for example `OSV database snapshot 2026-11-16: Go (sha256 ec23ddc864d6), npm (sha256 a6b0201971a8)`.
- **`osv_db`**: one ecosystem's OSV database. The pinned snapshot provides one per ecosystem (`@osv_db//:npm`). You can also build your own from a mirrored zip or from OSV JSON records.

No host osv-scanner needed. The binary is the upstream release for linux and darwin on amd64 and arm64, pinned by SHA-256 (osv-scanner 2.7.1), and downloaded only for the platform a build needs. The rules need `python3` (3.8+) on the host. The ignore file is parsed with `tomllib` on Python 3.11+, else with a vendored copy of tomli 2.2.1 (MIT).

## Install (Bzlmod)

```python
bazel_dep(name = "rules_osv", version = "0.1.0")
archive_override(
    module_name = "rules_osv",
    urls = ["https://github.com/collider-bazel-extensions/rules_osv/archive/refs/tags/v0.1.0.tar.gz"],
    strip_prefix = "rules_osv-0.1.0",
    integrity = "INTEGRITY_AFTER_TAG",
)

osv = use_extension("@rules_osv//:extensions.bzl", "osv")
use_repo(osv, "osv_db")
```

- **Toolchain:** rules_osv registers its toolchain, so nothing else is needed for osv-scanner.
- **`use_repo(osv, "osv_db")`:** makes the pinned snapshot visible as `@osv_db`. Each ecosystem's zip is its own repository, downloaded only when a test uses it. A Go-only repository never downloads npm's 221 MB.
- **Release archive:** the tag tarball leaves out `tests/` and `tools/`, so `bazel query @rules_osv//...` works for consumers.

## `osv_scan_test`

```python
load("@rules_osv//:defs.bzl", "osv_scan_test")

osv_scan_test(
    name = "vulnerabilities_test",
    lockfiles = [
        "pnpm-lock.yaml",
        "//services/api:go.mod",
    ],
    db = [
        "@osv_db//:npm",
        "@osv_db//:Go",
    ],
    ignore = "osv-scanner.toml",   # optional
)
```

On a finding the test fails, listing the lockfile, package, advisory IDs, fixed versions and aliases:

```
osv_scan //:vulnerabilities_test: osv-scanner 2.7.1, offline
  OSV database snapshot 2026-11-16: Go (sha256 ec23ddc864d6), npm (sha256 a6b0201971a8)
  lockfiles: pnpm-lock.yaml, services/api/go.mod

osv_scan //:vulnerabilities_test: 2 known vulnerabilities in 2 package(s):
  pnpm-lock.yaml  npm lodash@4.17.15  GHSA-p6mc-m468-83gw
      Prototype Pollution in lodash
      max CVSS 7.4; fixed in 4.17.19; aliases CVE-2020-8203
  services/api/go.mod  Go github.com/gin-gonic/gin@1.5.0  GO-2020-0001, GHSA-6vm3-jj99-7229
      Arbitrary log line injection in github.com/gin-gonic/gin
      max CVSS 7.5; fixed in 1.6.0; aliases CVE-2020-36567
Upgrade the package, or accept the finding with an entry in the ignore file (`ignore`): id, reason and effectiveUntil.
```

- **Offline, enforced:**
  - osv-scanner runs with `--offline` and reads only the databases in `db`.
  - The test is always tagged `block-network`, so under Bazel's sandbox it has no network at all.
  - Nothing else is implicit either:
    - Transitive resolution is off (`--offline` implies `--no-resolve`).
    - Call analysis is off (`--no-call-analysis=all`); Go's would run the host's `go`.
    - An `osv-scanner.toml` next to a lockfile is never read.
    - `OSV_SCANNER_*` variables are removed from the environment.
- **One database per ecosystem in the lockfiles.** If a lockfile has npm packages and `db` has no npm database, the test fails, saying so:

  ```
  osv_scan //:vulnerabilities_test: a lockfile has npm packages but `db` has no npm database (it has: Go). Add one, e.g. db = ["@osv_db//:npm"], ...
  ```

- **Workspace paths:** lockfiles are staged under their workspace paths, so findings name `services/api/go.mod`, for generated lockfiles too.
- **Reports:** JUnit goes to `$XML_OUTPUT_FILE`, with one test case per finding and per expired ignore entry. osv-scanner's JSON report goes to the test's undeclared outputs (`bazel-testlogs/<pkg>/<name>/test.outputs/osv-scanner.json`).

| Argument | Default | |
|---|---|---|
| `lockfiles` | | lockfiles to scan (required, non-empty); osv-scanner picks the parser by file name |
| `db` | | `osv_db` targets, at most one per ecosystem (required): `@osv_db//:<Ecosystem>` or your own |
| `ignore` | none | an `osv-scanner.toml` holding only `[[IgnoredVulns]]` (see below) |
| `env` | `{}` | test environment; `{"RULES_OSV_VENDORED_TOML": "1"}` forces the vendored TOML parser |

### Lockfiles

osv-scanner 2.7.1 reads the files in [its list](https://google.github.io/osv-scanner/supported-languages-and-lockfiles/), by file name: for example `pnpm-lock.yaml`, `package-lock.json`, `yarn.lock`, `bun.lock`, `go.mod`, `Cargo.lock`, `requirements.txt`, `poetry.lock`, `uv.lock`, `Pipfile.lock`, `pdm.lock`, `Gemfile.lock`, `composer.lock`, `packages.lock.json`, `gradle.lockfile`, `pom.xml`, `pubspec.lock`, `mix.lock`, `renv.lock` and `conan.lock`.

These are tested here: pnpm-lock.yaml, go.mod, Cargo.lock and requirements.txt.

Some files it does **not** read, and `osv_scan_test` fails on them with `osv-scanner can't read <path>: not a lockfile it supports`:
- **`MODULE.bazel.lock`.** osv-scanner 2.7.1 has no extractor for it, so Bazel module dependencies can't be scanned this way. MODULE.bazel.lock pins Bazel modules, which aren't an OSV ecosystem anyway. `MODULE.bazel` isn't read either: osv-scalibr's `bazelmaven` extractor (for `maven.install` artifacts) isn't in osv-scanner's default lockfile set. Scan the lockfiles your Bazel rules consume instead, such as a `pnpm-lock.yaml`, `go.mod`, `requirements_lock.txt` or `Cargo.lock`.
- **`go.sum`.** v2 reads `go.mod` only. v1 read `go.sum`.
- **`pom.xml`:** offline, only versions stated in the file are seen, with no parent POMs or transitive resolution.

`//tests:module_lock_fails_test` and `//tests:go_sum_fails_test` check the first two.

### The ignore file

The ignore file uses osv-scanner's own `osv-scanner.toml` format. rules_osv requires the reason and the expiry, which osv-scanner treats as optional:

```toml
[[IgnoredVulns]]
id = "GHSA-p6mc-m468-83gw"           # or any alias: CVE-2020-8203 works too
effectiveUntil = 2027-01-31          # a TOML date (unquoted), or a datetime
reason = "zipObjectDeep is not used; upgrade tracked in JIRA-123"
```

- **Required:** every entry needs `id`, a non-empty `reason`, and an expiry, `effectiveUntil` (or osv-scanner's deprecated `ignoreUntil`).
- **Malformed files fail clearly.** Unknown keys, a quoted date, duplicate ids, other tables (`[[PackageOverrides]]`) and invalid TOML each fail the test, listing every problem:

  ```
  osv_scan //:vulnerabilities_test: osv-scanner.toml: malformed ignore file:
    IgnoredVulns[0] (id GO-2020-0001): 'reason' is missing or empty: say why this finding is accepted
    IgnoredVulns[1] (id GHSA-p6mc-m468-83gw): effectiveUntil must be a TOML date such as 2027-01-31 (unquoted), not '2027-01-31'
  ```

- **Expired entries fail the test**, whether or not the finding is still there:
  - osv-scanner itself just stops applying an expired entry. Here the expired entry is also a failure, named with its date and reason, so it gets reviewed rather than silently dropped.
  - An entry dated `2027-01-31` expires at the start of that day, UTC.
  - Entries expiring within 30 days are noted in the output.
- **Matching is osv-scanner's:** an entry covers a finding if its id is any of the finding's IDs or aliases. Entries that match nothing are noted in the output, but don't fail the test.
- **Test caching:** a passing result is cached until an input changes, and expiry depends on today's date. So an entry that expires after the last run isn't caught until the test runs again. Run the scan uncached in CI (`--nocache_test_results`, or `tags = ["external"]`) to catch an expiry on the day.

## The OSV database

OSV publishes one zip of advisories per ecosystem at `https://osv-vulnerabilities.storage.googleapis.com/<Ecosystem>/all.zip`. Those URLs are rebuilt daily, so a sha256 pin on them would break within a day. rules_osv therefore pins **snapshots hosted as assets of its own GitHub releases**, one release per snapshot, tagged `db-YYYY-MM-DD`:

```
https://github.com/collider-bazel-extensions/rules_osv/releases/download/db-2026-11-16/npm-all.zip
```

The default snapshot is **2026-11-16**. Each zip is its own lazily fetched repository:

| Ecosystem | `@osv_db//:` | Size | Records |
|---|---|---|---|
| crates.io | `crates.io` | 3.9 MB | 3,148 |
| Go | `Go` | 12.9 MB | 9,955 |
| Maven | `Maven` | 10.5 MB | 7,257 |
| npm | `npm` | 221.5 MB | 232,512 |
| NuGet | `NuGet` | 2.8 MB | 2,014 |
| Packagist | `Packagist` | 11.1 MB | 7,449 |
| PyPI | `PyPI` | 38.0 MB | 26,943 |
| RubyGems | `RubyGems` | 5.3 MB | 5,532 |

npm is large because 224,360 of its 232,512 records are malicious-package reports (`MAL-`). The sha256s are in `private/db_snapshots.bzl`.

### Choosing a snapshot and ecosystems

Only the root module's `osv.db()` counts. It overrides rules_osv's own by `name`:

```python
osv = use_extension("@rules_osv//:extensions.bzl", "osv")

# An older pinned snapshot, offering only these ecosystems.
osv.db(date = "2026-11-16", ecosystems = ["Go", "npm"])
use_repo(osv, "osv_db")
```

### Your own snapshot or mirror

For a date rules_osv hasn't pinned, an internal mirror, or an ecosystem the default set lacks (Pub, Hex, CRAN, Hackage, ConanCenter, ...), pin the zips yourself:

```python
osv.db(
    name = "osv_db",                       # or another name, e.g. "osv_db_internal"
    date = "2026-12-01",                   # shown in test output
    url = "https://mirror.example.com/osv/{date}/{ecosystem}-all.zip",
    sha256 = {
        "Go": "…",
        "Pub": "…",
    },
)
use_repo(osv, "osv_db")
```

- `url` needs `{ecosystem}` and may use `{date}`. Any URL Bazel downloads works, including `file://`.
- For a pinned date, `sha256` replaces or adds individual ecosystems.
- `tools/snapshot_db.sh --out DIR [ecosystem ...]`, run from a rules_osv checkout, downloads today's zips and prints their shas.

Or write an `osv_db` target directly, from a zip or from OSV JSON records:

```python
load("@rules_osv//:defs.bzl", "osv_db")

osv_db(name = "go_db", ecosystem = "Go", snapshot = "internal-2026-12", zip = "Go-all.zip")
osv_db(name = "internal_db", ecosystem = "npm", snapshot = "internal", advisories = glob(["advisories/*.json"]))
```

- `ecosystem` is the OSV ecosystem name, exactly as osv-scanner names it (`Go`, `npm`, `PyPI`, `crates.io`, `Maven`, ...).
- With `advisories`, the records are zipped at build time, and each record must affect a package of that ecosystem.

### Before a snapshot's release exists

The zips are fetched by their pinned sha256, so you can supply them locally, for example while testing a new snapshot before uploading it:

```sh
bazel test //... --distdir=/path/to/osv-db-snapshot/db-2026-11-16
```

`--distdir` matches each download by file name (`npm-all.zip`) and sha256. A repository cache that already holds the zips works the same way.

## `osv.version()`

To pick another osv-scanner version, name it in your own `MODULE.bazel`. Only the root module's tag counts. For a version rules_osv hasn't pinned, give its shas, from the release's `osv-scanner_SHA256SUMS`:

```python
osv = use_extension("@rules_osv//:extensions.bzl", "osv")
osv.version(
    version = "2.7.0",
    sha256 = {"linux_amd64": "160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b"},
)
```

A platform without a sha fails only when its binary is fetched (a build on that platform), with `rules_osv: no sha256 for osv-scanner 2.7.0 on linux_arm64; add it to osv.version(sha256 = ...)`.

## Pinned versions

| Component | Version | Source |
|---|---|---|
| osv-scanner | `2.7.1` | google/osv-scanner releases (published `osv-scanner_SHA256SUMS`, each binary cross-checked) |
| OSV database | `2026-11-16` | osv.dev's per-ecosystem zips, re-hosted as the `db-2026-11-16` release assets |

- **Re-pinning osv-scanner:** `tools/update_versions.sh <version>` pins all four platforms from the checksums file, cross-checked against the downloads; `--check` verifies the pins. Then bump `DEFAULT_VERSION` and `osv.version()` in `MODULE.bazel` (`//tests:version_test` checks they agree).
- **Refreshing the database:** `tools/snapshot_db.sh` downloads today's zips into `../osv-db-snapshot/db-<date>/`, checks each is a complete zip of OSV records, and pins it in `private/db_snapshots.bzl`. It then prints the `gh release create db-<date> ...` command that uploads the zips. Upload before merging the pin, or consumers can't fetch it.

## Development

```sh
bazel test //tests/...                 # offline; the fixture database, no release assets needed
bazel test //tests:snapshot_test       # the real snapshot (downloads ~280 MB); manual
.github/consumer/check.sh /tmp/osv-consumer
```

See [DESIGN.md](DESIGN.md) for the design and trade-offs, and [CLAUDE.md](CLAUDE.md) for the repo layout and test inventory.

---

## Requesting a new rules package

Want Bazel rules for another tool or service?
[Request a rules package](https://github.com/collider-bazel-extensions/.github/issues/new?template=request-a-rules-package.yml).
The [organization page](https://github.com/collider-bazel-extensions) lists every package.
