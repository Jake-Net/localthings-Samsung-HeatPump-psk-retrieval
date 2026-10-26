"""Repeatedly probe the appliance for plaintext OCF replies (read-only).

Sends the three request variants the OCF libraries use, to the OCF multicast
group and to the subnet broadcast address, and logs any correlated reply.
"""
import secrets
import socket
import struct
import time

import cbor2

from smartthings_local.protocol.coap import (
    ACCEPT,
    CF_CBOR,
    METHOD_GET,
    TYPE_NON,
    URI_PATH,
    URI_QUERY,
    build_coap,
    parse_coap,
)

TARGET = "192.168.6.243"
IFACE = "192.168.6.235"
GROUP = "224.0.1.187"
BROADCAST = "192.168.6.255"
PORT = 5683
DURATION = 45

OCF_CBOR = (10000).to_bytes(2, "big")
OCF_VERSION_1_0 = (2048).to_bytes(2, "big")


def requests():
    base = [(URI_PATH, b"oic"), (URI_PATH, b"res")]
    yield build_coap(TYPE_NON, METHOD_GET, secrets.randbits(16),
                     secrets.token_bytes(8),
                     base + [(ACCEPT, OCF_CBOR), (2049, OCF_VERSION_1_0)])
    yield build_coap(TYPE_NON, METHOD_GET, secrets.randbits(16),
                     secrets.token_bytes(8),
                     base + [(ACCEPT, CF_CBOR)])
    yield build_coap(TYPE_NON, METHOD_GET, secrets.randbits(16),
                     secrets.token_bytes(8),
                     base + [(ACCEPT, CF_CBOR), (URI_QUERY, b"rt=oic.r.doxm")])


sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                socket.inet_aton(IFACE))
sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
sock.bind((IFACE, 0))
sock.setblocking(False)

started = time.monotonic()
next_send = 0.0
sends = 0
hits = 0
port2020 = 0
while time.monotonic() - started < DURATION:
    now = time.monotonic()
    if now >= next_send:
        for packet in requests():
            for dest in ((GROUP, PORT), (BROADCAST, PORT)):
                try:
                    sock.sendto(packet, dest)
                    sends += 1
                except OSError:
                    pass
        next_send = now + 2.0
    try:
        data, src = sock.recvfrom(8192)
    except BlockingIOError:
        time.sleep(0.05)
        continue
    except OSError:
        break
    if src[0] != TARGET:
        continue
    hits += 1
    try:
        mtype, code, mid, token, opts, payload = parse_coap(data)
    except Exception as exc:
        print("reply from %s:%d parse error %s" % (src[0], src[1], exc))
        continue
    print("REPLY from %s:%d type=%d code=%d.%02d options=%s bytes=%d" % (
        src[0], src[1], mtype, code >> 5, code & 0x1F, opts, len(payload or b"")))
    if payload:
        try:
            obj = cbor2.loads(payload)
            print("  cbor:", str(obj)[:600])
        except Exception as exc:
            print("  cbor decode failed:", exc)
    if hits >= 5:
        break

sock.close()
print("done: sends=%d replies=%d" % (sends, hits))
