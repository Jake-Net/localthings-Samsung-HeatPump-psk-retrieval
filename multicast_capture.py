"""Capture the appliance's plaintext /oic/res directory from the OCF multicast group.

Read-only. Replicates the modern OCF NON discovery request and follows Block2.
"""
import json
import secrets
import socket

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

GROUP = "224.0.1.187"
DISCOVERY_PORT = 5683
TARGET = "192.168.6.243"
IFACE = "192.168.6.235"

OCF_CBOR = (10000).to_bytes(2, "big")
OCF_VERSION_1_0 = (2048).to_bytes(2, "big")
BLOCK2 = 23


def block2_value(num, szx=6, more=True):
    raw = (num << 4) | (1 << 3 if more else 0) | szx
    return raw.to_bytes((raw.bit_length() + 7) // 8 or 1, "big")


def decode_block2(value):
    if not value:
        return 0, 6, False
    b = value
    num = (b[0] >> 4) & 0x0F
    for extra in b[1:]:
        num = (num << 8) | extra
    return num, b[0] & 0x07, bool(b[0] & 0x08)


def make_socket():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                    socket.inet_aton(IFACE))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
    sock.bind((IFACE, 0))
    sock.settimeout(4)
    return sock


def fetch(query=None):
    sock = make_socket()
    token = secrets.token_bytes(8)
    mid = secrets.randbits(16)
    payload = b""
    num = 0
    while True:
        options = [(URI_PATH, b"oic"), (URI_PATH, b"res"), (ACCEPT, OCF_CBOR)]
        if query:
            options.append((URI_QUERY, query))
        if num:
            options.append((BLOCK2, block2_value(num, 6, False)))
        options.append((2049, OCF_VERSION_1_0))
        sock.sendto(build_coap(TYPE_NON, METHOD_GET, mid, token, options),
                    (GROUP, DISCOVERY_PORT))
        deadline_hit = False
        while True:
            try:
                data, src = sock.recvfrom(8192)
            except socket.timeout:
                deadline_hit = True
                break
            if src[0] != TARGET:
                continue
            try:
                mtype, code, rmid, rtoken, ropts, body = parse_coap(data)
            except Exception:
                continue
            if rtoken != token or code >> 5 != 2:
                continue
            payload += body
            more = False
            for onum, oval in ropts:
                if onum == BLOCK2:
                    num, _szx, more = decode_block2(oval)
            if not more:
                sock.close()
                return payload
            num += 1
            break
        if deadline_hit:
            sock.close()
            return payload if payload else None


def summarise(payload, label):
    print("== %s (%d bytes) ==" % (label, len(payload) if payload else 0))
    if not payload:
        print("  no reply")
        return
    try:
        obj = cbor2.loads(payload)
    except Exception as exc:
        print("  cbor decode failed:", exc)
        print("  head:", payload[:120])
        return
    links = obj.get("links") if isinstance(obj, dict) else None
    if not isinstance(links, list):
        print("  top-level keys:", sorted(obj.keys()) if isinstance(obj, dict) else type(obj))
        print(json.dumps(obj, indent=2)[:2000])
        return
    print("  %d links" % len(links))
    for link in links:
        href = link.get("href")
        rt = link.get("rt")
        sec = link.get("sec")
        anchors = link.get("anchor")
        if sec is not None or "doxm" in str(href) or "cred" in str(href):
            print("   %-40s rt=%s sec=%s anchor=%s" % (href, rt, sec, anchors))
    print("  -- all hrefs --")
    print("   " + ", ".join(str(l.get("href")) for l in links))


if __name__ == "__main__":
    summarise(fetch(), "unfiltered /oic/res")
    summarise(fetch(b"rt=oic.r.doxm"), "filtered /oic/res?rt=oic.r.doxm")
