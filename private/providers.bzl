"""Providers exposed by rules_osv."""

OsvScannerInfo = provider(
    doc = "The osv-scanner toolchain binary.",
    fields = {
        "version": "string — pinned osv-scanner version",
        "osv_scanner": "File — the osv-scanner executable",
    },
)

OsvDbInfo = provider(
    doc = "One ecosystem's OSV database (osv_db): an all.zip of OSV records.",
    fields = {
        "ecosystem": "string — the OSV ecosystem, as osv-scanner names it (Go, npm, PyPI, crates.io, ...)",
        "snapshot": "string — which snapshot this is, shown in test output (e.g. 2026-11-16)",
        "sha256": "string — the zip's pinned sha256, or empty (shown in test output)",
        "zip": "File — the all.zip",
    },
)
