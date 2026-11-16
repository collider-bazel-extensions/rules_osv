"""osv_scanner_toolchain — exposes the platform-resolved `osv-scanner`
binary as a `ToolchainInfo`, so rules resolve it via
`ctx.toolchains["@rules_osv//toolchain:osv_scanner"]`.

`current_osv_scanner_toolchain` forwards the resolved binary as a plain
target (files + runfiles) for `data = [...]` use in tests.
"""

load("//private:providers.bzl", "OsvScannerInfo")

OSV_SCANNER_TOOLCHAIN_TYPE = Label("//toolchain:osv_scanner")

def _toolchain_impl(ctx):
    info = OsvScannerInfo(
        version = ctx.attr.version,
        osv_scanner = ctx.file.osv_scanner,
    )
    return [
        platform_common.ToolchainInfo(osv_scanner = info),
        DefaultInfo(
            files = depset([ctx.file.osv_scanner]),
            runfiles = ctx.runfiles(files = [ctx.file.osv_scanner]),
        ),
    ]

osv_scanner_toolchain = rule(
    implementation = _toolchain_impl,
    attrs = {
        "version": attr.string(mandatory = True),
        "osv_scanner": attr.label(allow_single_file = True, mandatory = True),
    },
)

def _current_impl(ctx):
    info = ctx.toolchains[OSV_SCANNER_TOOLCHAIN_TYPE].osv_scanner
    return [
        info,
        DefaultInfo(
            files = depset([info.osv_scanner]),
            runfiles = ctx.runfiles(files = [info.osv_scanner]),
        ),
    ]

current_osv_scanner_toolchain = rule(
    implementation = _current_impl,
    toolchains = [OSV_SCANNER_TOOLCHAIN_TYPE],
    doc = "The resolved osv-scanner binary, as files and runfiles.",
)
