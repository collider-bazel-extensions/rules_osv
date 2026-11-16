"""Public API for rules_osv.

  osv_scan_test  — test: no known vulnerabilities in these lockfiles,
                   matched offline against `db` (OSV database snapshots);
                   findings fail it unless an ignore entry (id, reason,
                   expiry) covers them, and an expired entry fails it
  osv_db         — one ecosystem's OSV database: an all.zip, or OSV JSON
                   records zipped at build time
"""

load("//private:db.bzl", _osv_db = "osv_db")
load("//private:providers.bzl", _OsvDbInfo = "OsvDbInfo", _OsvScannerInfo = "OsvScannerInfo")
load("//private:test.bzl", _osv_scan_test = "osv_scan_test")

osv_scan_test = _osv_scan_test
osv_db = _osv_db

OsvDbInfo = _OsvDbInfo
OsvScannerInfo = _OsvScannerInfo
