#!/usr/bin/env bash
# The sandbox gives tests tagged block-network no network, so the scans in
# this package couldn't reach osv.dev even if they tried: a TCP connection to
# osv's storage host (at whatever address it resolves to) or to fixed public
# addresses fails. Name resolution may still answer, through the host's
# resolver socket (systemd-resolved), but nothing can connect. Fails if any
# connection gets through, e.g. when the spawn strategy isn't a sandbox that
# can block the network.
set -euo pipefail
python3 -I - <<'PY'
import socket, sys
targets = [("8.8.8.8", 53), ("1.1.1.1", 443), ("142.250.80.27", 443)]
try:
    for info in socket.getaddrinfo("osv-vulnerabilities.storage.googleapis.com", 443, proto=socket.IPPROTO_TCP):
        targets.append((info[4][0], 443))
    print("note: osv-vulnerabilities.storage.googleapis.com resolves (host resolver); connecting must still fail")
except OSError as e:
    print("ok: name resolution blocked too (%s)" % e)
leaks = []
for host, port in targets:
    try:
        socket.create_connection((host, port), timeout=5).close()
        leaks.append("%s:%d" % (host, port))
    except OSError as e:
        print("ok: %s:%d unreachable (%s)" % (host, port, e))
if leaks:
    sys.exit("FAIL: connected from a block-network test to " + ", ".join(leaks))
print("PASS: no network in the test sandbox")
PY
