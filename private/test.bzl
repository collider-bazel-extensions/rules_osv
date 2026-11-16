"""osv_scan_test — fails on known vulnerabilities in lockfiles, offline.

osv-scanner reads the lockfiles (staged as real files under their
workspace paths) and matches their packages against the OSV databases in
`db` only: `--offline`, with the databases staged where its offline
matcher looks. Nothing is fetched at test time, and the test is tagged
`block-network`, so a sandboxed run has no network to fetch from.

Findings fail the test, except those an `ignore` entry covers. Every
ignore entry needs an id, a reason and an expiry (effectiveUntil); an
expired entry fails the test, naming it. The JSON report is written to
the undeclared outputs, JUnit to $XML_OUTPUT_FILE.
"""

load(":providers.bzl", "OsvDbInfo")

TOOLCHAIN = "//toolchain:osv_scanner"

def _shell_quote(s):
    return "'" + s.replace("'", "'\\''") + "'"

def _label_text(label):
    """//pkg:name in the main repository, else @repo//pkg:name."""
    if not label.workspace_name:
        return "//{}:{}".format(label.package, label.name)
    return str(label)

def _osv_scan_test_impl(ctx):
    tc = ctx.toolchains[TOOLCHAIN].osv_scanner
    if not ctx.files.lockfiles:
        fail("{}: lockfiles is empty: nothing to scan.".format(ctx.label))
    if not ctx.attr.db:
        fail("{}: db is empty: give the OSV databases of the lockfiles' ecosystems, e.g. db = [\"@osv_db//:npm\"].".format(ctx.label))
    dbs, seen = [], {}
    for t in ctx.attr.db:
        info = t[OsvDbInfo]
        if info.ecosystem in seen:
            fail("{}: db has two {} databases: {} and {}.".format(ctx.label, info.ecosystem, seen[info.ecosystem], t.label))
        seen[info.ecosystem] = t.label
        dbs.append(info)
    paths = {}
    for f in ctx.files.lockfiles:
        if f.short_path in paths:
            continue
        paths[f.short_path] = f
    manifest = ctx.actions.declare_file(ctx.label.name + ".osv_lockfiles")
    ctx.actions.write(manifest, "\n".join(paths.keys()) + "\n")

    args = [
        "--osv-scanner",
        tc.osv_scanner.short_path,
        "--version",
        tc.version,
        "--label",
        _label_text(ctx.label),
        "--manifest",
        manifest.short_path,
    ]
    for d in dbs:
        args += ["--db", "\t".join([d.ecosystem, d.snapshot, d.sha256, d.zip.short_path])]
    inputs = [tc.osv_scanner, manifest, ctx.file._driver] + ctx.files.lockfiles + [d.zip for d in dbs]
    if ctx.file.ignore:
        args += ["--ignore", ctx.file.ignore.short_path]
        inputs.append(ctx.file.ignore)

    driver = ctx.file._driver.short_path
    wrapper = ctx.actions.declare_file(ctx.label.name + ".sh")
    ctx.actions.expand_template(
        template = ctx.file._tmpl,
        output = wrapper,
        substitutions = {
            "__DRIVER__": driver,
            "__ARGS__": " ".join([_shell_quote(a) for a in args]),
        },
        is_executable = True,
    )
    runfiles = ctx.runfiles(files = [wrapper] + inputs + ctx.files._tomli)
    return [
        DefaultInfo(executable = wrapper, runfiles = runfiles),
        RunEnvironmentInfo(environment = ctx.attr.env),
    ]

_osv_scan_test = rule(
    implementation = _osv_scan_test_impl,
    test = True,
    doc = "Fails if osv-scanner finds known vulnerabilities in `lockfiles` (offline, against `db`).",
    attrs = {
        "lockfiles": attr.label_list(
            allow_files = True,
            doc = "Lockfiles to scan, named as osv-scanner expects: pnpm-lock.yaml, package-lock.json, go.mod, Cargo.lock, ...",
        ),
        "db": attr.label_list(
            providers = [OsvDbInfo],
            doc = "OSV databases, one per ecosystem: @osv_db//:npm, @osv_db//:Go, or your own osv_db targets.",
        ),
        "ignore": attr.label(
            allow_single_file = True,
            doc = "osv-scanner.toml-style [[IgnoredVulns]] (id, reason, effectiveUntil). Expired entries fail the test.",
        ),
        "env": attr.string_dict(
            doc = "Environment for the test, e.g. {\"RULES_OSV_VENDORED_TOML\": \"1\"} to force the vendored TOML parser.",
        ),
        "_driver": attr.label(default = "//private:osv.py", allow_single_file = True),
        "_tmpl": attr.label(default = "//private:run.sh.tmpl", allow_single_file = True),
        "_tomli": attr.label(default = "//private/third_party:tomli"),
    },
    toolchains = [TOOLCHAIN],
)

def osv_scan_test(name, tags = [], **kwargs):
    """osv_scan_test: always tagged `block-network` (a sandboxed run has no network).

    Args:
      name: the test's name.
      tags: extra tags; `block-network` is always added.
      **kwargs: lockfiles, db, ignore, and the usual test attributes.
    """
    _osv_scan_test(
        name = name,
        tags = tags + ([] if "block-network" in tags else ["block-network"]),
        **kwargs
    )
