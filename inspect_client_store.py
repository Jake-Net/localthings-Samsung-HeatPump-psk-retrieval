"""Inspect the emulator's SmartThings OCF credential store and device DB.

Read-only. Reports credential types (1 == PSK) and any registered devices.
"""
import sqlite3
import sys
from pathlib import Path

import cbor2

BASE = Path(r"C:\Users\kelly\Documents\Default Project\psk-retrieval\private\dump")


def inner(value):
    """Some OCF fields are CBOR byte strings wrapping more CBOR."""
    if isinstance(value, bytes):
        try:
            return cbor2.loads(value)
        except Exception:
            return value
    return value


def inspect_store(path):
    raw = path.read_bytes()
    print("== %s (%d bytes) ==" % (path.name, len(raw)))
    try:
        obj = cbor2.loads(raw)
    except Exception as exc:
        print("not top-level CBOR:", exc)
        for needle in (b"credtype", b"psk", b"iotivity"):
            print("  contains %r:" % needle, raw.lower().count(needle.lower()))
        return
    print("top-level keys:", sorted(obj.keys()) if isinstance(obj, dict) else type(obj))
    if not isinstance(obj, dict):
        return
    creds = inner(obj.get("cred"))
    if isinstance(creds, dict) and "creds" in creds:
        entries = creds["creds"]
        print("credential count:", len(entries))
        counts = {}
        for cred in entries:
            t = cred.get("credtype")
            counts[t] = counts.get(t, 0) + 1
        print("credtype counts (1=PSK):", counts)
        for cred in entries:
            if cred.get("credtype") == 1:
                private = cred.get("privatedata", {})
                print("  PSK subject:", cred.get("subjectuuid"),
                      "encoding:", private.get("encoding"),
                      "data present:", bool(private.get("data")))
        if 1 not in counts:
            print("NO PSK credential present in this store")
    doxm = inner(obj.get("doxm"))
    if isinstance(doxm, dict):
        print("doxm sct:", doxm.get("sct"), "owned:", doxm.get("owned"),
              "devowneruuid:", doxm.get("devowneruuid"))


def inspect_db(path):
    print("== %s ==" % path.name)
    con = sqlite3.connect(str(path))
    try:
        tables = [r[0] for r in con.execute(
            "select name from sqlite_master where type='table'")]
        print("tables:", tables)
        if "T_DEVICE_LIST" in tables:
            cols = [r[1] for r in con.execute("pragma table_info(T_DEVICE_LIST)")]
            print("T_DEVICE_LIST columns:", cols)
            for row in con.execute("select * from T_DEVICE_LIST"):
                print("  row:", row)
    finally:
        con.close()


if __name__ == "__main__":
    inspect_store(BASE / "oic_svr_db_client.dat")
    print()
    inspect_db(BASE / "PDM.db")
