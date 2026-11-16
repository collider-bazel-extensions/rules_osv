"""Analysis-time tests: providers, executables, the block-network tag, and
the analysis errors for bad attributes."""

load("@bazel_skylib//lib:unittest.bzl", "analysistest", "asserts")
load("//:defs.bzl", "OsvDbInfo", "osv_db", "osv_scan_test")

def _db_info_impl(ctx):
    env = analysistest.begin(ctx)
    info = analysistest.target_under_test(env)[OsvDbInfo]
    asserts.equals(env, "Go", info.ecosystem)
    asserts.equals(env, "fixture", info.snapshot)
    asserts.equals(env, "all.zip", info.zip.basename)
    asserts.true(env, info.zip.path.endswith("/osv_db/Go/all.zip"), "zip at " + info.zip.path)
    return analysistest.end(env)

_db_info_test = analysistest.make(_db_info_impl)

def _db_zip_impl(ctx):
    env = analysistest.begin(ctx)
    info = analysistest.target_under_test(env)[OsvDbInfo]
    asserts.equals(env, "npm", info.ecosystem)
    asserts.equals(env, "0" * 64, info.sha256)
    asserts.true(env, info.zip.is_source, "a given zip is used as is")
    return analysistest.end(env)

_db_zip_test = analysistest.make(_db_zip_impl)

def _scan_impl(ctx):
    env = analysistest.begin(ctx)
    target = analysistest.target_under_test(env)
    exe = target[DefaultInfo].files_to_run.executable
    asserts.true(env, exe != None, "expected an executable")
    runfiles = [f.basename for f in target[DefaultInfo].default_runfiles.files.to_list()]
    for want in ["osv.py", "osv-scanner", "all.zip", "go.mod", "all.toml", "_parser.py"]:
        asserts.true(env, want in runfiles, "{} not in runfiles: {}".format(want, runfiles))
    return analysistest.end(env)

_scan_test = analysistest.make(_scan_impl)

def _fails_impl(ctx):
    env = analysistest.begin(ctx)
    asserts.expect_failure(env, ctx.attr.message)
    return analysistest.end(env)

_fails_test = analysistest.make(
    _fails_impl,
    expect_failure = True,
    attrs = {"message": attr.string()},
)

def analysis_test_suite(name):
    s = name + "_subject"
    m = ["manual"]
    osv_db(name = s + "_zip_db", ecosystem = "npm", snapshot = "s", sha256 = "0" * 64, zip = "//tests/testdata:empty.zip", tags = m)
    osv_scan_test(
        name = s + "_scan",
        db = ["//tests/testdata:db_Go"],
        ignore = "//tests/testdata:ignore/all.toml",
        lockfiles = ["//tests/testdata:vulnerable/go.mod"],
        tags = m,
    )
    osv_scan_test(name = s + "_no_lockfiles", db = ["//tests/testdata:db_Go"], lockfiles = [], tags = m)
    osv_scan_test(name = s + "_no_db", db = [], lockfiles = ["//tests/testdata:clean/go.mod"], tags = m)
    osv_scan_test(
        name = s + "_two_go",
        db = ["//tests/testdata:db_Go", ":" + s + "_go_again"],
        lockfiles = ["//tests/testdata:clean/go.mod"],
        tags = m,
    )
    osv_db(name = s + "_go_again", advisories = ["//tests/testdata:db/Go/GO-2020-0001.json"], ecosystem = "Go", snapshot = "s", tags = m)
    osv_db(name = s + "_both", advisories = ["//tests/testdata:db/Go/GO-2020-0001.json"], ecosystem = "Go", snapshot = "s", zip = "//tests/testdata:empty.zip", tags = m)
    osv_db(name = s + "_neither", ecosystem = "Go", snapshot = "s", tags = m)
    osv_db(name = s + "_bad_eco", advisories = ["//tests/testdata:db/Go/GO-2020-0001.json"], ecosystem = "GitHub Actions", snapshot = "s", tags = m)
    osv_db(name = s + "_no_snapshot", advisories = ["//tests/testdata:db/Go/GO-2020-0001.json"], ecosystem = "Go", snapshot = "", tags = m)

    tests = {
        "_db_info": (_db_info_test, "//tests/testdata:db_Go", None),
        "_db_zip": (_db_zip_test, ":" + s + "_zip_db", None),
        "_scan": (_scan_test, ":" + s + "_scan", None),
        "_no_lockfiles": (_fails_test, ":" + s + "_no_lockfiles", "lockfiles is empty"),
        "_no_db": (_fails_test, ":" + s + "_no_db", "db is empty"),
        "_two_go": (_fails_test, ":" + s + "_two_go", "db has two Go databases"),
        "_both": (_fails_test, ":" + s + "_both", "give exactly one of `zip`"),
        "_neither": (_fails_test, ":" + s + "_neither", "give exactly one of `zip`"),
        "_bad_eco": (_fails_test, ":" + s + "_bad_eco", "ecosystem 'GitHub Actions'"),
        "_no_snapshot": (_fails_test, ":" + s + "_no_snapshot", "snapshot is empty"),
    }
    for suffix, (rule, target, message) in tests.items():
        if message:
            rule(name = name + suffix, target_under_test = target, message = message)
        else:
            rule(name = name + suffix, target_under_test = target)
    native.test_suite(name = name, tests = [":" + name + t for t in tests])
