"""Search SmartThings on-device databases for the heat pump device record.

Read-only. Copies were pulled from the emulator together with their WAL/SHM
files so SQLite can replay uncommitted pages.
"""
import sqlite3
from pathlib import Path

BASE = Path(r"C:\Users\kelly\Documents\Default Project\psk-retrieval\private\dump")

NEEDLES = ("ehs", "heat", "192.168.6.243", "sac", "wifikit", "mim")


def dump_db(path):
    print("== %s ==" % path.name)
    try:
        con = sqlite3.connect(str(path))
    except Exception as exc:
        print("  open failed:", exc)
        return
    try:
        tables = [r[0] for r in con.execute(
            "select name from sqlite_master where type='table'")]
        for table in tables:
            try:
                cur = con.execute('select * from "%s"' % table)
            except Exception as exc:
                print("  %s: %s" % (table, exc))
                continue
            cols = [d[0] for d in cur.description]
            rows = cur.fetchall()
            hits = []
            for row in rows:
                text = " ".join(str(v) for v in row if v is not None).lower()
                if any(n in text for n in NEEDLES):
                    hits.append(row)
            print("  %s: %d rows, %d matches" % (table, len(rows), len(hits)))
            for row in hits[:3]:
                pairs = [(c, v) for c, v in zip(cols, row)
                         if v not in (None, "", b"")]
                print("     ", pairs[:12])
    finally:
        con.close()


if __name__ == "__main__":
    for name in ("DataLayerData.db", "CloudDb.db", "DeviceGroupData.db",
                 "NearbyRegisteredDevice.db", "BackgroundDeviceData.db"):
        path = BASE / name
        if path.exists():
            dump_db(path)
            print()
