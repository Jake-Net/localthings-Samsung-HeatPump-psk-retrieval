"""Probe an OCF appliance for unauthenticated CoAP resources. Read-only."""
import socket
import struct
import sys

import cbor2

HOST = sys.argv[1] if len(sys.argv) > 1 else "192.168.6.243"


def build(mid, path):
    out = bytes([0x40, 0x01]) + struct.pack("!H", mid)
    last = 0
    for seg in path:
        delta = 11 - last
        last = 11
        out += bytes([(delta << 4) | len(seg)]) + seg.encode()
    return out


def parse(data):
    tkl = data[0] & 0x0F
    code = data[1]
    idx = 4 + tkl
    while idx < len(data):
        b = data[idx]
        if b == 0xFF:
            return code, data[idx + 1:]
        idx += 1
        d, l = b >> 4, b & 0x0F
        if d == 13:
            idx += 1
        elif d == 14:
            idx += 2
        if l == 13:
            idx += 1
        elif l == 14:
            idx += 2
        idx += l
    return code, None


def probe(port, path, mid):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(4)
    try:
        sock.sendto(build(mid, path), (HOST, port))
        data, addr = sock.recvfrom(8192)
        code, payload = parse(data)
        print("port %d /%s -> reply %d.%02d %d bytes" % (
            port, "/".join(path), code >> 5, code & 0x1F, len(data)))
        if payload:
            try:
                obj = cbor2.loads(payload)
                print("   cbor keys:", sorted(obj.keys()) if isinstance(obj, dict) else type(obj))
            except Exception as exc:
                print("   cbor decode failed:", exc)
        return True
    except socket.timeout:
        print("port %d /%s -> timeout" % (port, "/".join(path)))
    except Exception as exc:
        print("port %d /%s -> %s" % (port, "/".join(path), exc))
    finally:
        sock.close()
    return False


if __name__ == "__main__":
    mid = 0x2000
    for port in (5683, 5684):
        for path in (["oic", "res"], ["oic", "d"], ["oic", "sec", "doxm"]):
            mid += 1
            probe(port, path, mid)
