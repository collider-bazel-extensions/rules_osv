"""Bzlmod extension `osv`, two tag classes:

  osv.version(version, sha256 = {})
      the osv-scanner binary: an `osv_scanner_<platform>` repo per platform.
  osv.db(name = "osv_db", date = "", ecosystems = [], url = "", sha256 = {})
      an OSV database snapshot: a hub repo `@<name>` with one osv_db target
      per ecosystem (`@osv_db//:npm`), each zip in its own lazily fetched
      repo `@<name>_<Ecosystem>`.

rules_osv's own tags are the base and the root module's override them (for
`db`, by name), so a consumer declares nothing to get the pinned binary and
snapshot. Other modules' tags are ignored. Versions and snapshots not in
private/ can be pinned in the tags themselves (sha256).
"""

load("//private:db.bzl", "valid_ecosystem")
load("//private:db_snapshots.bzl", "DB_SNAPSHOTS", "DB_URL", "DEFAULT_DB_DATE")
load("//private:repositories.bzl", "osv_db_hub_repo", "osv_db_zip_repo", "osv_scanner_binary_repo")
load("//private:versions.bzl", "DEFAULT_VERSION", "OSV_SCANNER_VERSIONS", "PLATFORMS")

_version_tag = tag_class(attrs = {
    "version": attr.string(mandatory = True),  # e.g. "2.7.1"
    # Pins for a version not in OSV_SCANNER_VERSIONS (or to replace a known
    # version's), by platform, from the release's osv-scanner_SHA256SUMS. A
    # platform without one fails only when a build needs that platform.
    "sha256": attr.string_dict(),
})

_db_tag = tag_class(attrs = {
    "name": attr.string(default = "osv_db"),
    # YYYY-MM-DD; empty = rules_osv's DEFAULT_DB_DATE.
    "date": attr.string(),
    # Which ecosystems the hub offers; empty = every ecosystem pinned for the
    # date (or in `sha256`). Unused ones are never downloaded either way.
    "ecosystems": attr.string_list(),
    # Download URL template with {ecosystem} (and optionally {date}), for a
    # mirror; empty = this repository's release assets (DB_URL).
    "url": attr.string(),
    # Ecosystem -> sha256 of its zip: required for a date not in
    # DB_SNAPSHOTS, or replaces the pinned value.
    "sha256": attr.string_dict(),
})

def _version_pins(mod):
    pins = {}
    for tag in mod.tags.version:
        p = struct(version = tag.version, sha256 = dict(tag.sha256))
        prev = pins.get("v")
        if prev != None and prev != p:
            fail("rules_osv: {} sets osv.version() twice, differently ({} and {}); set one.".format(
                "the root module" if mod.is_root else mod.name,
                prev.version,
                p.version,
            ))
        pins["v"] = p
    return pins.get("v")

def _db_pins(mod):
    dbs = {}
    for tag in mod.tags.db:
        p = struct(
            date = tag.date,
            ecosystems = list(tag.ecosystems),
            url = tag.url,
            sha256 = dict(tag.sha256),
        )
        prev = dbs.get(tag.name)
        if prev != None and prev != p:
            fail("rules_osv: {} sets osv.db(name = \"{}\") twice, differently; set one.".format(
                "the root module" if mod.is_root else mod.name,
                tag.name,
            ))
        dbs[tag.name] = p
    return dbs

def _create_binaries(pins):
    version = pins.version
    for plat in pins.sha256:
        if plat not in PLATFORMS:
            fail("rules_osv: osv.version(sha256 = ...) has unknown platform '{}'. Platforms: {}".format(
                plat,
                sorted(PLATFORMS.keys()),
            ))
    if version not in OSV_SCANNER_VERSIONS and not pins.sha256:
        fail("rules_osv: osv.version(version = \"{}\") is not supported. Supported: {}. ".format(
            version,
            ", ".join(sorted(OSV_SCANNER_VERSIONS.keys())),
        ) + "For another version, pin it yourself: osv.version(version = ..., sha256 = {<platform>: <sha256>}) (from the release's osv-scanner_SHA256SUMS).")
    for plat in PLATFORMS.keys():
        osv_scanner_binary_repo(
            name = "osv_scanner_" + plat,
            version = version,
            platform = plat,
            sha256 = pins.sha256.get(plat, ""),
        )

def _create_db(name, pins):
    date = pins.date or DEFAULT_DB_DATE
    parts = date.split("-")
    if len(parts) != 3 or [len(p) for p in parts] != [4, 2, 2] or not "".join(parts).isdigit():
        fail("rules_osv: osv.db(name = \"{}\", date = \"{}\"): the date must be YYYY-MM-DD.".format(name, date))
    known = DB_SNAPSHOTS.get(date, {})
    if not known and not pins.sha256:
        fail("rules_osv: osv.db(name = \"{}\", date = \"{}\") is not a pinned snapshot. Pinned: {}. ".format(
            name,
            date,
            ", ".join(sorted(DB_SNAPSHOTS.keys())),
        ) + "For another snapshot (your own mirror, say), pin it: osv.db(date = ..., url = \"https://.../{ecosystem}-all.zip\", sha256 = {<Ecosystem>: <sha256>}).")
    shas = {eco: p["sha256"] for eco, p in known.items()}
    shas.update(pins.sha256)
    ecosystems = pins.ecosystems or sorted(shas.keys())
    url = pins.url or DB_URL
    if "{ecosystem}" not in url:
        fail("rules_osv: osv.db(name = \"{}\", url = \"{}\"): the url needs an {{ecosystem}} placeholder.".format(name, url))
    hub = {}
    for eco in ecosystems:
        if not valid_ecosystem(eco):
            fail("rules_osv: osv.db(name = \"{}\"): ecosystem '{}': letters, digits, '.', '_' and '-' only.".format(name, eco))
        if eco not in shas:
            fail("rules_osv: osv.db(name = \"{}\", date = \"{}\"): no {} database is pinned for that date (pinned: {}); add it to sha256 = {{\"{}\": ...}}.".format(
                name,
                date,
                eco,
                ", ".join(sorted(shas.keys())) or "none",
                eco,
            ))
        osv_db_zip_repo(
            name = name + "_" + eco,
            url = url.replace("{ecosystem}", eco).replace("{date}", date),
            sha256 = shas[eco],
        )
        hub[eco] = shas[eco]
    osv_db_hub_repo(
        name = name,
        date = date,
        name_prefix = name,
        ecosystems = hub,
    )

def _impl(mctx):
    own_version, root_version = None, None
    own_dbs, root_dbs = {}, {}
    for mod in mctx.modules:
        if mod.is_root:
            root_version = _version_pins(mod)
            root_dbs = _db_pins(mod)
        elif mod.name == "rules_osv":
            own_version = _version_pins(mod)
            own_dbs = _db_pins(mod)

    # One binary per platform: the root's version, else ours, else the default.
    _create_binaries(root_version or own_version or struct(version = DEFAULT_VERSION, sha256 = {}))

    dbs = dict(own_dbs)
    dbs.update(root_dbs)
    for name, pins in dbs.items():
        _create_db(name, pins)

osv = module_extension(
    implementation = _impl,
    tag_classes = {
        "version": _version_tag,
        "db": _db_tag,
    },
)
