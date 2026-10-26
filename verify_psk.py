import sys
import uuid

from smartthings_local.protocol.auth import PskAuth
from smartthings_local.protocol.dtls_session import DtlsCoapSession

host = sys.argv[1] if len(sys.argv) > 1 else "192.168.6.243"
identity = uuid.UUID("debaee55-70a7-8239-be5a-54e6e48f1058").bytes
key = bytes.fromhex("377326f3f65c2e7311a7bea844586350")

auth = PskAuth(identity=identity, key=key)
sess = DtlsCoapSession(host, 5684, auth=auth)
try:
    sess.connect()
    sess.start_reader()
    code, body = sess.get(["oic", "d"], timeout=10.0)
    print("GET /oic/d ->", code)
    print("body bytes:", len(body) if body is not None else None)
    print("body repr:", repr(body)[:800])
finally:
    try:
        sess.close()
    except Exception:
        pass
