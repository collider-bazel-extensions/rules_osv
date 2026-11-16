"""osv-scanner binary pins.

One release binary per platform from google/osv-scanner (a single static
Go executable, not an archive):

    https://github.com/google/osv-scanner/releases/download/v<ver>/osv-scanner_<os>_<arch>

SHA-256s are the release's published `osv-scanner_SHA256SUMS`, each
cross-checked against the downloaded binary. Maintainer flow:

    tools/update_versions.sh <ver>     # add / re-pin <ver> from the checksums file
    tools/update_versions.sh --check   # verify every pin, no writes

//tests:checksums_test fails on an empty or malformed value.
"""

# The version the `osv` extension fetches when the root module names none.
DEFAULT_VERSION = "2.7.1"

OSV_SCANNER_VERSIONS = {
    "2.7.1": {
        "linux_amd64": {
            "url": "https://github.com/google/osv-scanner/releases/download/v2.7.1/osv-scanner_linux_amd64",
            "sha256": "fb7dab19a8bd9bbe5c3189f09d4b7ee1820c9553a23bac202648a56efd2f6ee8",
        },
        "linux_arm64": {
            "url": "https://github.com/google/osv-scanner/releases/download/v2.7.1/osv-scanner_linux_arm64",
            "sha256": "983d22fbad9724514e3fcc6acc83b5fa64c5ffa6b0d9f510028f22c1b223ff81",
        },
        "darwin_amd64": {
            "url": "https://github.com/google/osv-scanner/releases/download/v2.7.1/osv-scanner_darwin_amd64",
            "sha256": "b8420d5485ba792626315f1bf9a5a2046e971d38eea75bf9090c38852dbc3b1b",
        },
        "darwin_arm64": {
            "url": "https://github.com/google/osv-scanner/releases/download/v2.7.1/osv-scanner_darwin_arm64",
            "sha256": "b22c02877a811c8f78956e8643efa554932b7378f590d13f8e97d4e9448a29f3",
        },
    },
}

# {version}, {platform}: the binary of a version pinned in osv.version()
# itself (not in OSV_SCANNER_VERSIONS).
OSV_SCANNER_URL = "https://github.com/google/osv-scanner/releases/download/v{version}/osv-scanner_{platform}"

PLATFORMS = {
    "linux_amd64": ["@platforms//os:linux", "@platforms//cpu:x86_64"],
    "linux_arm64": ["@platforms//os:linux", "@platforms//cpu:arm64"],
    "darwin_amd64": ["@platforms//os:osx", "@platforms//cpu:x86_64"],
    "darwin_arm64": ["@platforms//os:osx", "@platforms//cpu:arm64"],
}
