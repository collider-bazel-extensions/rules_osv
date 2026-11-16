# Test data

- `db/<Ecosystem>/*.json`: real OSV records from the 2026-11-16 snapshot
  (osv.dev's export; pretty-printed, otherwise unchanged), zipped by
  `osv_db(advisories = ...)` into the fixture database:
  - Go: GO-2020-0001 (gin < 1.6.0);
  - npm: GHSA-p6mc-m468-83gw and GHSA-35jh-r3h4-6jhm (lodash < 4.17.19, < 4.17.21);
  - crates.io: RUSTSEC-2021-0003 (smallvec 1.0.0 to 1.6.1);
  - PyPI: PYSEC-2019-217 and GHSA-462w-v97r-4m45 (jinja2 < 2.10.1; aliases
    of each other, so osv-scanner reports one group).

  The records are published by osv.dev under its source databases' terms
  (CC-BY 4.0 for GitHub advisories and PyPA, CC0 for Go and RustSec).
- `vulnerable/`, `clean/`: the same four lockfiles (pnpm-lock.yaml, go.mod,
  Cargo.lock, requirements.txt) naming a version the records above affect,
  or one they don't. "Clean" is relative to the fixture database: the real
  snapshot has later advisories for some of those versions.
- `ignore/`: ignore files. `all.toml` covers every vulnerable finding until
  2099; `expired*.toml` hold expired entries; the rest are malformed.
- `unsupported/`: lockfiles osv-scanner 2.7.1 can't read: `go.sum`, and a
  `MODULE.bazel.lock` generated from `module_bazel_lock.json` (this
  repository never commits a file named MODULE.bazel.lock).
