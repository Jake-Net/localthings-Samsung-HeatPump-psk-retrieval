"""Unauthenticated CoAP GET of /oic/sec/doxm.

Read-only. Reports the security scheme (sct) and the owner UUID, which is the
PSK identity used by LocalThings. Sends one confirmable GET; no writes.
"""
import socket
import struct
import sys

import cbor2

HOST = sys.argv[1] if len(sys.argv) > 1 else "192.168.6.243"
PORT = 5683
PATH = ["oic", "sec", "doxm"]
TIMEOUT = 6


def build_request(mid):
    # ver=1, type=CON(0), tkl=0
    out = bytes([0x40, 0x01]) + struct.pack("!H", mid)
    last = 0
    for seg in PATH:
        delta = 11 - last
        last = 11
        out += bytes([(delta << 4) | len(seg)]) + seg.encode()
    return out


def parse(data):
    ver_type_tkl = data[0]
    tkl = ver_type_tkl & 0x0F
    code = data[1]
    idx = 4 + tkl
    number = 0
    while idx < len(data):
        b = data[idx]
        if b == 0xFF:
            idx += 1
            return code, data[idx:]
        delta = b >> 4
        length = b & 0x0F
        idx += 1
        if delta == 13:
            delta = data[idx] + 13
            idx += 1
        elif delta == 14:
            delta = struct.unpack("!H", data[idx:idx + 2])[0] + 269
            idx += 2
        if length == 13:
            length = data[idx] + 13
            idx += 1
        elif length == 14:
            length = struct.unpack("!H", data[idx:idx + 2])[0] + 269
            idx += 2
        number += delta
        idx += length
    return code, None


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT)
    mid = 0x1234
    sock.sendto(build_request(mid), (HOST, PORT))
    try:
        data, addr = sock.recvfrom(4096)
    except socket.timeout:
        print("No reply from %s:%d (UDP). Check the appliance is on and CoAP 5683 is reachable." % (HOST, PORT))
        return 1
    code, payload = parse(data)
    print("reply from %s code=%d.%02d bytes=%d" % (addr[0], code >> 5, code & 0x1F, len(data)))
    if payload is None:
        print("No payload in reply")
        return 1
    doxm = cbor2.loads(payload)
    print("doxm keys:", sorted(doxm.keys()))
    sct = doxm.get("sct")
    print("sct:", sct, "(bit1 set + bit8 clear => PSK)")
    for field in ("devowneruuid", "rowneruuid", "dpc", "owned"):
        if field in doxm:
            print("%s: %r" % (field, doxm[field]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
