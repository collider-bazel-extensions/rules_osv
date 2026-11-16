"""osv_db — one ecosystem's OSV database, as osv-scanner reads it offline.

The pinned snapshots (`@osv_db//:<Ecosystem>`, from the `osv` extension)
are osv_db targets over a downloaded all.zip. Write your own for a
database you build or mirror yourself, from a zip or from OSV JSON records:

    osv_db(name = "go_db", ecosystem = "Go", snapshot = "internal-2026-11", zip = "Go-all.zip")
    osv_db(name = "fixture_db", ecosystem = "npm", snapshot = "fixture",
           advisories = glob(["advisories/*.json"]))
"""

load(":providers.bzl", "OsvDbInfo")

_NAME_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"

def valid_ecosystem(eco):
    """True for an OSV ecosystem name rules_osv can stage as a directory."""
    if not eco or not eco[0].isalnum():
        return False
    for c in eco.elems():
        if c not in _NAME_CHARS:
            return False
    return True

def _osv_db_impl(ctx):
    eco = ctx.attr.ecosystem
    if not valid_ecosystem(eco):
        fail("{}: ecosystem '{}': use the OSV ecosystem name (Go, npm, PyPI, crates.io, Maven, ...); letters, digits, '.', '_' and '-' only.".format(ctx.label, eco))
    if not ctx.attr.snapshot:
        fail("{}: snapshot is empty: name the snapshot (its date, say), so test output shows which database was used.".format(ctx.label))
    if bool(ctx.file.zip) == bool(ctx.files.advisories):
        fail("{}: give exactly one of `zip` (an all.zip) and `advisories` (OSV JSON records).".format(ctx.label))
    if ctx.file.zip:
        zipfile = ctx.file.zip
    else:
        zipfile = ctx.actions.declare_file(ctx.label.name + "/osv_db/{}/all.zip".format(eco))
        args = ctx.actions.args()
        args.add(ctx.file._driver)
        args.add("make-db")
        args.add("--out", zipfile)
        args.add("--ecosystem", eco)
        args.add_all(ctx.files.advisories)
        ctx.actions.run_shell(
            command = 'exec python3 "$@"',
            arguments = [args],
            inputs = [ctx.file._driver] + ctx.files.advisories,
            outputs = [zipfile],
            use_default_shell_env = True,
            mnemonic = "OsvMakeDb",
            progress_message = "Zipping %{label}'s OSV records",
        )
    return [
        OsvDbInfo(
            ecosystem = eco,
            snapshot = ctx.attr.snapshot,
            sha256 = ctx.attr.sha256,
            zip = zipfile,
        ),
        DefaultInfo(files = depset([zipfile]), runfiles = ctx.runfiles(files = [zipfile])),
    ]

osv_db = rule(
    implementation = _osv_db_impl,
    doc = "One ecosystem's OSV database: an all.zip of OSV records, for osv_scan_test's `db`.",
    attrs = {
        "ecosystem": attr.string(
            mandatory = True,
            doc = "OSV ecosystem name, exactly as osv-scanner names it: Go, npm, PyPI, crates.io, Maven, ...",
        ),
        "snapshot": attr.string(
            mandatory = True,
            doc = "Which snapshot this is (a date, say); osv_scan_test prints it.",
        ),
        "zip": attr.label(
            allow_single_file = [".zip"],
            doc = "An all.zip as osv.dev exports it (one JSON record per file).",
        ),
        "advisories": attr.label_list(
            allow_files = [".json"],
            doc = "OSV JSON records to zip into the database; each must affect a package of `ecosystem`.",
        ),
        "sha256": attr.string(
            doc = "The zip's pinned sha256, for display only (the download already verified it).",
        ),
        "_driver": attr.label(default = "//private:osv.py", allow_single_file = True),
    },
)
