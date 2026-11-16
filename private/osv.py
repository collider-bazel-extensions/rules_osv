#!/usr/bin/env python3
"""rules_osv driver. Runs on the host's python3 (3.8+); the TOML ignore
file is parsed with tomllib (3.11+), else the vendored tomli 2.2.1
(third_party/), so the shape check runs on every host.

Modes:
  scan            osv_scan_test: stage lockfiles under their workspace paths
                  and the database zips under the layout osv-scanner reads
                  offline (<dir>/osv-scalibr/<Ecosystem>/all.zip), run
                  `osv-scanner scan source --offline`, apply the ignore file
                  (reason + expiry required; expired entries fail), report.
  make-db         osv_db(advisories = ...): zip OSV JSON records into an
                  all.zip, deterministically.
  check-ignore    validate an ignore file's shape and expiries, nothing else.

Exit codes (scan): 0 clean; 1 findings or expired ignore entries; 2 a bad
ignore file, a missing database or osv-scanner failing.
"""

import argparse
import datetime
import json
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from xml.sax.saxutils import escape, quoteattr

sys.dont_write_bytecode = True  # no __pycache__ in runfiles or the vendored tomli

IGNORE_KEYS = ("id", "reason", "effectiveUntil", "ignoreUntil")


class Fatal(Exception):
    """An error that fails the run with exit code 2 and this message."""


# ---- runfiles ---------------------------------------------------------------

def runfile(short_path):
    """A runfiles path (File.short_path) -> a path on disk."""
    root = os.environ.get("RUNFILES_DIR") or os.environ.get("TEST_SRCDIR")
    if not root:
        return short_path
    if short_path.startswith("../"):
        return os.path.join(root, short_path[3:])
    return os.path.join(root, "_main", short_path)


def workspace_path(short_path):
    """External files keep their repository: external/<repo>/<path>."""
    if short_path.startswith("../"):
        return "external/" + short_path[3:]
    return short_path


# ---- the ignore file ----------------------------------------------------------

def _toml():
    """(module, name): tomllib (3.11+), else the vendored tomli 2.2.1.
    RULES_OSV_VENDORED_TOML=1 forces tomli."""
    if os.environ.get("RULES_OSV_VENDORED_TOML") != "1":
        try:
            import tomllib
            return tomllib, "tomllib"
        except ImportError:
            pass
    # Next to the driver in runfiles (not via its realpath, which would be
    # the source tree outside the sandbox).
    tp = os.path.join(os.path.dirname(os.path.abspath(__file__)), "third_party")
    if os.path.isdir(os.path.join(tp, "tomli")) and tp not in sys.path:
        sys.path.insert(0, tp)
    import tomli
    return tomli, "tomli " + getattr(tomli, "__version__", "")


def _until_instant(value):
    """A TOML date or datetime -> an aware UTC datetime. A date means the
    start of that day (UTC), as osv-scanner reads a date (at midnight)."""
    if isinstance(value, datetime.datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=datetime.timezone.utc)
        return value.astimezone(datetime.timezone.utc)
    return datetime.datetime(value.year, value.month, value.day, tzinfo=datetime.timezone.utc)


def load_ignore(path, shown):
    """-> (list of entry dicts (id, reason, until, until_key, until_text,
    index), the TOML parser used). Raises Fatal on any shape error, listing
    every problem."""
    toml, parser = _toml()
    try:
        with open(path, "rb") as f:
            data = toml.load(f)
    except Exception as e:  # tomllib.TOMLDecodeError, or tomli's
        raise Fatal("{}: not valid TOML: {}".format(shown, e))
    errs = []
    for key in data:
        if key != "IgnoredVulns":
            errs.append("unknown top-level key '{}': a rules_osv ignore file holds only "
                        "[[IgnoredVulns]] entries".format(key))
    raw = data.get("IgnoredVulns", [])
    if not isinstance(raw, list) or any(not isinstance(e, dict) for e in raw):
        errs.append("IgnoredVulns must be an array of tables ([[IgnoredVulns]])")
        raw = []
    entries, seen = [], {}
    for i, e in enumerate(raw):
        vid = e.get("id")
        where = "IgnoredVulns[{}]".format(i) + (" (id {})".format(vid) if isinstance(vid, str) and vid else "")
        for key in e:
            if key not in IGNORE_KEYS:
                errs.append("{}: unknown key '{}' (known: {})".format(where, key, ", ".join(IGNORE_KEYS)))
        if not isinstance(vid, str) or not vid.strip():
            errs.append("{}: 'id' is missing or empty".format(where))
        elif vid in seen:
            errs.append("{}: duplicate id, also IgnoredVulns[{}]".format(where, seen[vid]))
        else:
            seen[vid] = i
        reason = e.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            errs.append("{}: 'reason' is missing or empty: say why this finding is accepted".format(where))
        keys = [k for k in ("effectiveUntil", "ignoreUntil") if k in e]
        until = None
        if not keys:
            errs.append("{}: no expiry: set effectiveUntil = <date>, e.g. effectiveUntil = 2027-01-31".format(where))
        elif len(keys) > 1:
            errs.append("{}: both effectiveUntil and ignoreUntil: keep effectiveUntil".format(where))
        else:
            v = e[keys[0]]
            if isinstance(v, (datetime.date, datetime.datetime)):
                until = _until_instant(v)
            else:
                errs.append("{}: {} must be a TOML date such as 2027-01-31 (unquoted), not {!r}".format(
                    where, keys[0], v))
        if until is not None and isinstance(vid, str) and isinstance(reason, str):
            entries.append({
                "id": vid.strip(),
                "reason": " ".join(reason.split()),
                "until": until,
                "until_key": keys[0],
                "until_text": e[keys[0]].isoformat(),
                "index": i,
            })
    if errs:
        raise Fatal("{}: malformed ignore file:\n".format(shown) +
                    "\n".join("  " + m for m in errs) +
                    "\nEach entry needs an id, a reason and an expiry:\n"
                    "  [[IgnoredVulns]]\n  id = \"GHSA-xxxx-xxxx-xxxx\"\n"
                    "  effectiveUntil = 2027-01-31\n  reason = \"why this finding is accepted\"")
    return entries, parser


def split_expired(entries, now):
    live, expired = [], []
    for e in entries:
        (expired if e["until"] <= now else live).append(e)
    return live, expired


# ---- osv-scanner --------------------------------------------------------------

def _stage_lockfiles(manifest, root):
    """manifest lines: <runfiles path>. Copies each to root/<workspace path>.
    -> list of workspace paths."""
    out = []
    with open(manifest) as f:
        for line in f:
            short = line.rstrip("\n")
            if not short:
                continue
            ws = workspace_path(short)
            dst = os.path.join(root, ws)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copyfile(runfile(short), dst)
            out.append(ws)
    return out


def _stage_dbs(dbs, root):
    """dbs: (ecosystem, snapshot, sha256, runfiles path). Links each zip as
    root/osv-scalibr/<ecosystem>/all.zip, the layout osv-scanner's offline
    matcher reads under --local-db-path."""
    for eco, _, _, short in dbs:
        d = os.path.join(root, "osv-scalibr", eco)
        os.makedirs(d, exist_ok=True)
        src = os.path.realpath(runfile(short))
        if not os.path.isfile(src):
            raise Fatal("the {} database zip is missing: {}".format(eco, short))
        os.symlink(src, os.path.join(d, "all.zip"))


def _scanner_failure(rc, output, stage, dbs):
    lines = [l for l in output.splitlines() if l.strip()]
    ecos = sorted({eco for eco, _, _, _ in dbs})
    for l in lines:
        if "could not load db for " in l and " ecosystem" in l:
            eco = l.split("could not load db for ", 1)[1].split(" ecosystem", 1)[0]
            return ("a lockfile has {eco} packages but `db` has no {eco} database "
                    "(it has: {have}). Add one, e.g. db = [\"@osv_db//:{eco}\"], and make sure "
                    "osv.db() lists the {eco} ecosystem.").format(eco=eco, have=", ".join(ecos) or "none")
    for l in lines:
        if "could not determine extractor suitable to this file" in l:
            path = l.split(":", 1)[1].strip().strip('"')
            if path.startswith(stage + os.sep):
                path = path[len(stage) + 1:]
            return ("osv-scanner can't read {}: not a lockfile it supports (see the README's "
                    "list). osv-scanner picks the parser by file name.").format(path)
    if rc == 128:
        return "osv-scanner found no packages in the lockfiles."
    shown = "\n".join("  " + l.replace(stage + os.sep, "") for l in lines[-20:])
    return "osv-scanner failed (exit {}):\n{}".format(rc, shown)


def _scanner_version(scanner):
    """The binary's own version ("osv-scanner version: 2.7.1"), or ""."""
    try:
        out = subprocess.run([scanner, "--version"], stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, text=True, errors="replace").stdout
    except OSError as e:
        raise Fatal("can't run osv-scanner: {}".format(e))
    for line in out.splitlines():
        if line.startswith("osv-scanner version:"):
            return line.split(":", 1)[1].strip()
    return ""


def run_scanner(scanner, lockfiles, stage, dbroot, config, raw_json):
    cmd = [scanner, "scan", "source",
           "--offline",                  # = --offline-vulnerabilities --no-resolve
           "--no-call-analysis=all",     # Go call analysis would run the host's go
           "--local-db-path=" + dbroot,
           "--config=" + config,         # never an osv-scanner.toml found next to a lockfile
           "--format=json",
           "--output-file=" + raw_json]
    cmd += ["--lockfile=" + os.path.join(stage, p) for p in lockfiles]
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("OSV_SCANNER_", "OSV_SCALIBR_"))}
    env["HOME"] = os.path.dirname(dbroot)
    p = subprocess.run(cmd, cwd=stage, env=env, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, text=True, errors="replace")
    return p.returncode, p.stdout


def _fixed_versions(vuln, pkg_name, eco):
    fixed = []
    for a in vuln.get("affected", []) or []:
        p = a.get("package", {}) or {}
        if p.get("name") != pkg_name or (p.get("ecosystem") or "").split(":")[0] != eco:
            continue
        for r in a.get("ranges", []) or []:
            for ev in r.get("events", []) or []:
                if "fixed" in ev and ev["fixed"] not in fixed:
                    fixed.append(ev["fixed"])
    return fixed


def findings_from(report, stage):
    """osv-scanner's JSON -> list of findings, one per (lockfile, package,
    alias group), as osv-scanner groups them."""
    out = []
    for res in report.get("results", []) or []:
        path = res.get("source", {}).get("path", "")
        if path.startswith(stage + os.sep):
            path = path[len(stage) + 1:]
        for pv in res.get("packages", []) or []:
            pkg = pv.get("package", {}) or {}
            vulns = {v.get("id"): v for v in pv.get("vulnerabilities", []) or []}
            for g in pv.get("groups", []) or []:
                ids = list(g.get("ids", []) or [])
                aliases = list(g.get("aliases", []) or ids)
                first = vulns.get(ids[0], {}) if ids else {}
                summary = next((vulns.get(i, {}).get("summary") for i in ids
                                if vulns.get(i, {}).get("summary")), "")
                out.append({
                    "path": path,
                    "name": pkg.get("name", ""),
                    "version": pkg.get("version", ""),
                    "ecosystem": pkg.get("ecosystem", ""),
                    "ids": ids,
                    "aliases": sorted(set(aliases) | set(ids)),
                    "severity": g.get("max_severity", "") or "",
                    "summary": summary,
                    "fixed": _fixed_versions(first, pkg.get("name", ""), pkg.get("ecosystem", "")),
                })
    return out


def apply_ignores(findings, live):
    """As osv-scanner does: a group is ignored when any of its IDs or
    aliases is an ignore entry's id. -> (kept, ignored [(finding, entry)])."""
    by_id = {e["id"]: e for e in live}
    kept, ignored = [], []
    for f in findings:
        hit = next((by_id[a] for a in f["aliases"] if a in by_id), None)
        if hit:
            hit["used"] = True
            ignored.append((f, hit))
        else:
            kept.append(f)
    return kept, ignored


def _days(td):
    return td.days if td.days else 0


def write_junit(path, label, findings, expired):
    cases = []
    for f in findings:
        name = "{}: {}@{} {}".format(f["path"], f["name"], f["version"], "/".join(f["ids"]))
        msg = f["summary"] or ", ".join(f["aliases"])
        cases.append('  <testcase classname={} name={}><failure message={}>{}</failure></testcase>'.format(
            quoteattr(label), quoteattr(name), quoteattr(msg), escape(", ".join(f["aliases"]))))
    for e in expired:
        name = "ignore {} (expired {})".format(e["id"], e["until_text"])
        cases.append('  <testcase classname={} name={}><failure message={}>{}</failure></testcase>'.format(
            quoteattr(label), quoteattr(name), quoteattr("expired ignore entry"), escape(e["reason"])))
    if not cases:
        cases.append('  <testcase classname={} name="no findings"/>'.format(quoteattr(label)))
    failures = len(findings) + len(expired)
    with open(path, "w") as f:
        f.write('<?xml version="1.0" encoding="UTF-8"?>\n<testsuites>\n'
                '<testsuite name={} tests="{}" failures="{}">\n{}\n</testsuite>\n</testsuites>\n'.format(
                    quoteattr(label), len(cases), failures, "\n".join(cases)))


def scan(a):
    dbs = []
    for spec in a.db:
        eco, snapshot, sha, short = spec.split("\t")
        dbs.append((eco, snapshot, sha, short))
    scanner = runfile(a.osv_scanner)
    ignore_shown = workspace_path(a.ignore) if a.ignore else ""

    snapshots = {}
    for eco, snapshot, sha, _ in dbs:
        snapshots.setdefault(snapshot, []).append(eco + (" (sha256 {})".format(sha[:12]) if sha else ""))
    real = _scanner_version(scanner)
    print("osv_scan {}: osv-scanner {}, offline".format(a.label, real or a.version))
    if real and real != a.version:
        print("  note: the toolchain says osv-scanner {}, the binary says {}".format(a.version, real))
    for snap in sorted(snapshots):
        print("  OSV database snapshot {}: {}".format(snap, ", ".join(sorted(snapshots[snap], key=str.lower))))

    now = datetime.datetime.now(datetime.timezone.utc)
    entries, parser = load_ignore(runfile(a.ignore), ignore_shown) if a.ignore else ([], "")
    live, expired = split_expired(entries, now)
    if a.ignore:
        print("  ignore file {}: {} entr{} in effect, {} expired (parsed with {})".format(
            ignore_shown, len(live), "y" if len(live) == 1 else "ies", len(expired), parser))

    tmp = tempfile.mkdtemp(prefix="osv_scan.", dir=os.environ.get("TEST_TMPDIR"))
    try:
        stage = os.path.join(tmp, "ws")
        dbroot = os.path.join(tmp, "db")
        os.makedirs(stage)
        lockfiles = _stage_lockfiles(runfile(a.manifest), stage)
        print("  lockfiles: {}".format(", ".join(lockfiles)))
        _stage_dbs(dbs, dbroot)
        config = os.path.join(tmp, "osv-scanner.toml")
        open(config, "w").close()  # ignores are applied below, not by osv-scanner
        raw = os.path.join(tmp, "osv-scanner.json")
        rc, output = run_scanner(scanner, lockfiles, stage, dbroot, config, raw)
        if rc not in (0, 1):
            raise Fatal(_scanner_failure(rc, output, stage, dbs))
        with open(raw) as f:
            report = json.load(f)
        if a.json:
            shutil.copyfile(raw, a.json)
        findings = findings_from(report, stage)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    kept, ignored = apply_ignores(findings, live)
    if a.junit:
        write_junit(a.junit, a.label, kept, expired)

    for f, e in ignored:
        print("  ignored  {}@{} {} ({}): {} [until {}]".format(
            f["name"], f["version"], "/".join(f["ids"]), f["path"], e["reason"], e["until_text"]))
    for e in live:
        left = (e["until"] - now).days
        if left < 30:
            print("  note: ignore entry {} expires in {} day{} ({} = {})".format(
                e["id"], left, "" if left == 1 else "s", e["until_key"], e["until_text"]))
    for e in live:
        if not e.get("used"):
            print("  note: ignore entry {} matched no finding; remove it once it is no longer needed".format(e["id"]))

    failed = False
    if kept:
        failed = True
        print("\nosv_scan {}: {} known vulnerabilit{} in {} package(s):".format(
            a.label, len(kept), "y" if len(kept) == 1 else "ies",
            len({(f["path"], f["name"], f["version"]) for f in kept})))
        for f in sorted(kept, key=lambda f: (f["path"], f["name"], f["ids"])):
            print("  {}  {} {}@{}  {}".format(
                f["path"], f["ecosystem"], f["name"], f["version"], ", ".join(f["ids"])))
            others = [x for x in f["aliases"] if x not in f["ids"]]
            detail = []
            if f["severity"]:
                detail.append("max CVSS " + f["severity"])
            if f["fixed"]:
                detail.append("fixed in " + ", ".join(f["fixed"]))
            if others:
                detail.append("aliases " + ", ".join(others))
            if f["summary"]:
                print("      " + f["summary"])
            if detail:
                print("      " + "; ".join(detail))
        print("Upgrade the package, or accept the finding with an entry in the ignore file "
              "(`ignore`): id, reason and effectiveUntil.")
    if expired:
        failed = True
        print("\nosv_scan {}: {} expired ignore entr{} in {}:".format(
            a.label, len(expired), "y" if len(expired) == 1 else "ies", ignore_shown))
        for e in expired:
            print("  {}  {} = {} (expired {} days ago)  reason: {}".format(
                e["id"], e["until_key"], e["until_text"], _days(now - e["until"]), e["reason"]))
        print("An expired entry no longer applies. Review it: fix the dependency and remove "
              "the entry, or set a new effectiveUntil if the reason still holds.")
    if failed:
        return 1
    print("PASS: no known vulnerabilities{}.".format(
        " ({} ignored)".format(len(ignored)) if ignored else ""))
    return 0


# ---- make-db, check-ignore ----------------------------------------------------

def make_db(a):
    records = {}
    for path in a.advisories:
        try:
            with open(path, "rb") as f:
                content = f.read()
            rec = json.loads(content)
        except (OSError, ValueError) as e:
            raise Fatal("{}: not an OSV JSON record: {}".format(path, e))
        vid = rec.get("id") if isinstance(rec, dict) else None
        if not vid:
            raise Fatal("{}: not an OSV record (no id)".format(path))
        ecos = {(x.get("package", {}) or {}).get("ecosystem", "").split(":")[0]
                for x in rec.get("affected", []) or []}
        if a.ecosystem not in ecos:
            raise Fatal("{}: {} affects no {} package (ecosystems: {})".format(
                path, vid, a.ecosystem, ", ".join(sorted(e for e in ecos if e)) or "none"))
        name = vid + ".json"
        if name in records:
            raise Fatal("{}: {} is given twice".format(path, vid))
        records[name] = content
    with zipfile.ZipFile(a.out, "w", zipfile.ZIP_DEFLATED) as z:
        for name in sorted(records):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            z.writestr(info, records[name])
    return 0


def check_ignore(a):
    now = datetime.datetime.now(datetime.timezone.utc)
    entries, _ = load_ignore(a.ignore, a.ignore)
    live, expired = split_expired(entries, now)
    for e in expired:
        print("expired: {} ({} = {})".format(e["id"], e["until_key"], e["until_text"]))
    print("{}: {} entries, {} expired".format(a.ignore, len(entries), len(expired)))
    return 1 if expired else 0


def main(argv):
    p = argparse.ArgumentParser(prog="osv.py", fromfile_prefix_chars=None)
    sub = p.add_subparsers(dest="mode", required=True)
    s = sub.add_parser("scan")
    s.add_argument("--osv-scanner", required=True)
    s.add_argument("--version", required=True)
    s.add_argument("--label", required=True)
    s.add_argument("--manifest", required=True)
    s.add_argument("--db", action="append", default=[])
    s.add_argument("--ignore", default="")
    s.add_argument("--json", default="")
    s.add_argument("--junit", default="")
    m = sub.add_parser("make-db")
    m.add_argument("--out", required=True)
    m.add_argument("--ecosystem", required=True)
    m.add_argument("advisories", nargs="+")
    c = sub.add_parser("check-ignore")
    c.add_argument("ignore")
    a = p.parse_args(argv)
    try:
        return {"scan": scan, "make-db": make_db, "check-ignore": check_ignore}[a.mode](a)
    except Fatal as e:
        label = getattr(a, "label", "")
        print("\n{}: {}".format("osv_scan " + label if label else "rules_osv", e))
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
