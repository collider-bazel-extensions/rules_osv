# Vendored third-party code

## tomli 2.2.1

- Source: https://pypi.org/project/tomli/2.2.1/ (sdist `tomli-2.2.1.tar.gz`,
  sha256 `cd45e1dc79c835ce60f7404ec8119f2eb06d38b1deba146f07ced3bbc44505ff`),
  `src/tomli/*.py` unmodified. The same copy as rules_gitleaks'.
- License: MIT (`tomli/LICENSE`).
- Why: `osv_scan_test` parses the ignore file (an osv-scanner.toml) with the
  standard library's `tomllib`, which needs Python 3.11. On older Pythons
  (3.8+) the driver uses this copy instead, so the shape and expiry checks
  run everywhere. `RULES_OSV_VENDORED_TOML=1` forces it, for tests.
