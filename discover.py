"""Discover whether the appliance exposes OCF locally (read-only).

1. SSDP M-SEARCH (OCF uses SSDP for discovery).
2. CoAP GET with a token to the usual OCF resources on 5683.
Nothing is written to the device.
"""
import socket
import struct
import sys

HOST = sys.argv[1] if len(sys.argv) > 1 else "192.168.6.243"


def ssdp():
    print("== SSDP M-SEARCH ==")
    msg = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 2\r\n"
        "ST: ssdp:all\r\n"
        "\r\n"
    ).encode()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    sock.settimeout(5)
    sock.sendto(msg, ("239.255.255.250", 1900))
    seen = set()
    try:
        while True:
            data, addr = sock.recvfrom(4096)
            key = (addr[0], data[:40])
            if key in seen:
                continue
            seen.add(key)
            text = data.decode("utf-8", "replace")
            print("  from %s:%d" % addr)
            for line in text.splitlines()[:12]:
                if line.strip():
                    print("    " + line.strip())
            if len(seen) >= 6:
                break
    except socket.timeout:
        if not seen:
            print("  no SSDP replies")
    finally:
        sock.close()


def build_coap(mid, path, token=b"\x01\x02\x03\x04"):
    # ver=1, type=CON(0), tkl=len(token)
    out = bytes([0x40 | len(token), 0x01]) + struct.pack("!H", mid) + token
    last = 0
    for seg in path:
        delta = 11 - last
        last = 11
        out += bytes([(delta << 4) | len(seg)]) + seg.encode()
    return out


def coap(path, mid):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(4)
    try:
        sock.sendto(build_coap(mid, path), (HOST, 5683))
        data, addr = sock.recvfrom(8192)
        tkl = data[0] & 0x0F
        code = data[1]
        print("  /%s -> %d.%02d (%d bytes)" % (
            "/".join(path), code >> 5, code & 0x1F, len(data)))
        return True
    except socket.timeout:
        print("  /%s -> timeout" % "/".join(path))
    except Exception as exc:
        print("  /%s -> %s" % ("/".join(path), exc))
    finally:
        sock.close()
    return False


if __name__ == "__main__":
    ssdp()
    print("== CoAP ==")
    for i, path in enumerate((["oic", "res"], ["oic", "d"],
                              ["oic", "sec", "doxm"], ["oic", "p"])):
        coap(path, 0x3100 + i)
