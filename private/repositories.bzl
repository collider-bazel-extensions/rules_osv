"""Repository rules for rules_osv.

  osv_scanner_<platform>  the osv-scanner release binary at the pinned sha,
                          with that platform's toolchain implementation, so
                          the repo name doesn't change with the version.
  <db>_<Ecosystem>        one ecosystem's all.zip of a pinned OSV snapshot.
  <db>                    the database hub: an osv_db target per ecosystem
                          (`@osv_db//:npm`), each pointing at its own zip
                          repo. A zip downloads only when a build needs it.
"""

load(":versions.bzl", "OSV_SCANNER_URL", "OSV_SCANNER_VERSIONS")

_BINARY_BUILD = """\
load("{toolchain_bzl}", "osv_scanner_toolchain")

package(default_visibility = ["//visibility:public"])

exports_files(["osv-scanner"])

osv_scanner_toolchain(
    name = "toolchain_impl",
    version = "{version}",
    osv_scanner = "osv-scanner",
)
"""

def _binary_impl(rctx):
    version = rctx.attr.version
    platform = rctx.attr.platform
    pin = OSV_SCANNER_VERSIONS.get(version, {}).get(platform, {})
    sha256 = rctx.attr.sha256 or pin.get("sha256", "")
    if not sha256:
        fail("rules_osv: no sha256 for osv-scanner {} on {}; add it to osv.version(sha256 = {{\"{}\": ...}}) (from the release's osv-scanner_SHA256SUMS).".format(
            version,
            platform,
            platform,
        ))
    rctx.download(
        url = pin.get("url") or OSV_SCANNER_URL.format(version = version, platform = platform),
        output = "osv-scanner",
        sha256 = sha256,
        executable = True,
    )
    rctx.file("BUILD.bazel", _BINARY_BUILD.format(
        toolchain_bzl = str(Label("//toolchain:toolchain.bzl")),
        version = version,
    ))

osv_scanner_binary_repo = repository_rule(
    implementation = _binary_impl,
    attrs = {
        "version": attr.string(mandatory = True),
        "platform": attr.string(mandatory = True),
        # Replaces OSV_SCANNER_VERSIONS' pin; required for a version not there.
        "sha256": attr.string(),
    },
)

def _db_zip_impl(rctx):
    rctx.download(
        url = rctx.attr.url,
        output = "all.zip",
        sha256 = rctx.attr.sha256,
    )
    rctx.file("BUILD.bazel", 'exports_files(["all.zip"], visibility = ["//visibility:public"])\n')

osv_db_zip_repo = repository_rule(
    implementation = _db_zip_impl,
    doc = "One ecosystem's all.zip of an OSV snapshot, at a pinned sha256.",
    attrs = {
        "url": attr.string(mandatory = True),
        "sha256": attr.string(mandatory = True),
    },
)

_HUB_HEADER = """\
# OSV database snapshot {date}: one osv_db per ecosystem. Each zip is its
# own repository (@{name}_<Ecosystem>), downloaded only when a build uses it.
load("{db_bzl}", "osv_db")

package(default_visibility = ["//visibility:public"])
"""

_HUB_DB = """
osv_db(
    name = "{eco}",
    ecosystem = "{eco}",
    sha256 = "{sha256}",
    snapshot = "{date}",
    zip = "@{repo}//:all.zip",
)
"""

def _db_hub_impl(rctx):
    chunks = [_HUB_HEADER.format(
        date = rctx.attr.date,
        name = rctx.attr.name_prefix,
        db_bzl = str(Label("//private:db.bzl")),
    )]
    for eco, sha256 in rctx.attr.ecosystems.items():
        chunks.append(_HUB_DB.format(
            eco = eco,
            sha256 = sha256,
            date = rctx.attr.date,
            repo = rctx.attr.name_prefix + "_" + eco,
        ))
    rctx.file("BUILD.bazel", "".join(chunks))

osv_db_hub_repo = repository_rule(
    implementation = _db_hub_impl,
    doc = "The database hub: osv_db targets named by ecosystem.",
    attrs = {
        "date": attr.string(mandatory = True),
        # The hub's apparent name, which prefixes its zip repos' names.
        "name_prefix": attr.string(mandatory = True),
        # Ecosystem -> its zip's sha256 (shown in test output).
        "ecosystems": attr.string_dict(mandatory = True),
    },
)
