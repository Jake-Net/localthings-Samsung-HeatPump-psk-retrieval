import base64
import hashlib
import hmac
import io
import json
import sys
import uuid
from pathlib import Path

import cbor2
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

datenc = Path(sys.argv[1]).read_bytes()
key = bytes.fromhex(sys.argv[2])
outpath = Path(sys.argv[3]) if len(sys.argv) > 3 else None

iv, ct, mac = datenc[:16], datenc[16:-32], datenc[-32:]
if not hmac.compare_digest(hmac.new(key, ct, hashlib.sha256).digest(), mac):
    raise SystemExit("MAC failed")
dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
padded = dec.update(ct) + dec.finalize()
size = len(datenc) - 64 + (iv[15] & 15)
plain = padded[:size]
stream = io.BytesIO(plain)
store = cbor2.CBORDecoder(stream).decode()

cred = store["cred"]
if isinstance(cred, bytes):
    cred = cbor2.loads(cred)

print("MAC + CBOR OK")
print("doxm:", store.get("doxm"))
print("cred owner (rowneruuid):", cred.get("rowneruuid"))
print("credential count:", len(cred.get("creds", [])))

results = []
for c in cred.get("creds", []):
    row = {
        "credid": c.get("credid"),
        "subjectuuid": c.get("subjectuuid"),
        "credtype": c.get("credtype"),
        "credusage": c.get("credusage"),
    }
    priv = c.get("privatedata") or c.get("privateData")
    if isinstance(priv, dict):
        priv = priv.get("data")
    if priv is not None:
        if isinstance(priv, str):
            try:
                priv = base64.b64decode(priv)
            except Exception:
                priv = priv.encode()
        row["data_len"] = len(priv)
        if c.get("credtype") == 1:
            row["psk_hex"] = priv.hex()
    results.append(row)
    print(row)

psks = [r for r in results if r["credtype"] == 1]
print("PSK count:", len(psks))

if outpath and psks:
    ident = cred.get("rowneruuid")
    rec = {
        "device_id": psks[0]["subjectuuid"],
        "psk_identity": ident,
        "psk_hex": psks[0]["psk_hex"],
        "identity_contains_nul": "\u0000" in str(uuid.UUID(ident).bytes),
        "all_psks": psks,
    }
    outpath.parent.mkdir(parents=True, exist_ok=True)
    outpath.write_text(json.dumps(rec, indent=2), encoding="utf-8")
    print("saved:", outpath)
