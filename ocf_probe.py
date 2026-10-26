"""Find the appliance's plaintext OCF response port and read public resources.

Read-only: uses the smartthings-local discovery helpers.
"""
import cbor2

from smartthings_local.protocol.ocf_discovery import read_plaintext_ocf_resource
from smartthings_local.protocol.ocf_multicast import discover_ocf_responder_ports

IP = "192.168.6.243"
IFACE = "192.168.6.235"

print("discovering responder ports ...")
result = discover_ocf_responder_ports(IP, interface_address=IFACE)
ports = list(result.ports)
print("ports:", ports)

candidates = [5683] + [p for p in ports if p != 5683]
for port in candidates:
    for path in ("/oic/sec/doxm", "/oic/d", "/oic/res"):
        try:
            res = read_plaintext_ocf_resource(IP, path, port=port)
        except Exception as exc:
            print(port, path, "error:", exc)
            continue
        print(port, path, "successful=%s complete=%s code=%s" % (
            res.successful, res.complete, getattr(res, "code", None)))
        if res.successful:
            try:
                obj = cbor2.loads(res.payload)
                if isinstance(obj, dict):
                    print("   keys:", sorted(obj.keys()))
                    for key in ("sct", "owned", "devowneruuid", "rowneruuid",
                                "di", "n", "rt"):
                        if key in obj:
                            print("   %s: %r" % (key, obj[key]))
                else:
                    print("   type:", type(obj).__name__)
            except Exception as exc:
                print("   cbor decode failed:", exc)
        elif res.complete:
            print("   body:", res.payload[:200])
        else:
            print("   error_code:", getattr(res, "error_code", None))
