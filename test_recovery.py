"""Offline checks using synthetic credentials only; never contact a device."""
import base64
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import uuid

import cbor2
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import hmac

import inspect_encrypted_store as recovery

spec = importlib.util.spec_from_file_location("save_oven_key", Path(__file__).with_name("save-oven-key.py"))
saver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(saver)

# Deliberately synthetic byte sequences, not appliance or account identifiers.
TARGET = uuid.UUID(bytes=bytes(range(16, 32)))
OWNER = uuid.UUID(bytes=bytes(range(16)))
KEY = bytes(range(32))


def fixture():
    return {"rowneruuid": str(OWNER), "creds": [{
        "subjectuuid": str(TARGET), "credtype": 1,
        "privatedata": {"encoding": "oic.sec.encoding.base64",
                        "data": base64.b64encode(KEY[:16]).decode()},
    }]}


def encrypted(plain):
    iv = bytes(15) + bytes([len(plain) & 15])
    padded = plain + bytes(16 - len(plain) % 16)
    encoder = Cipher(algorithms.AES(KEY), modes.CBC(iv)).encryptor()
    ciphertext = encoder.update(padded) + encoder.finalize()
    return iv + ciphertext + hmac.digest(KEY, ciphertext, "sha256")


class FakeAdb:
    """Records calls and answers the fixed set of adb invocations read_store makes."""

    def __init__(self, *, version="1.8.51.30", code="185130010", abi="arm64-v8a",
                 shell_is_root=True, su_is_root=True, present=True, pid="123",
                 port="45678", store=b""):
        self.version, self.code, self.abi = version, code, abi
        self.shell_is_root, self.su_is_root, self.present = shell_is_root, su_is_root, present
        self.pid, self.port, self.store = pid, port, store
        self.calls = []

    def __call__(self, *args):
        self.calls.append(list(args))
        joined = " ".join(args)
        if args[:2] == ("shell", "id"):
            return b"uid=0(root)\n" if self.shell_is_root else b"uid=2000(shell)\n"
        if args[0] == "exec-out" and args[1].startswith("su"):
            return b"uid=0(root)\n" if self.su_is_root else b""
        if args[:2] == ("shell", "dumpsys"):
            if not self.present:
                return b"no such package\n"
            return (f"Package [{recovery.PACKAGE}]\n"
                    f"versionName={self.version}\n"
                    f"versionCode={self.code} minSdk=31\n").encode()
        if args[:2] == ("shell", "getprop"):
            return self.abi.encode() + b"\n"
        if args[:2] == ("shell", "pidof"):
            return (self.pid + "\n").encode() if self.pid else b""
        if args[:2] == ("shell", "am"):
            return b""
        if args[:1] == ("forward",) and args[1] == "tcp:0":
            return (self.port + "\n").encode()
        if args[:1] == ("forward",) and args[1] == "--remove":
            return b""
        if args[0] == "exec-out":
            return self.store
        return b""


def frida_result(*keys):
    body = "".join("RECOVERY_KEY:" + base64.b64encode(k).decode() + "\n" for k in keys)
    return subprocess.CompletedProcess([], 0, body, "")


class RecoveryTests(unittest.TestCase):
    def test_decoder_roundtrips_and_mac_rejection(self):
        recovery.selftest()
        data = encrypted(cbor2.dumps({"cred": cbor2.dumps(fixture())}))
        store = recovery.decode_cbor(recovery.decrypt(KEY, data))
        self.assertEqual(recovery.credential_section(store), fixture())
        with self.assertRaises(ValueError):
            recovery.decrypt(KEY, data[:20] + bytes([data[20] ^ 1]) + data[21:])

    def test_invalid_lengths_and_trailing_cbor(self):
        for key, data in ((KEY[:-1], bytes(64)), (KEY, bytes(63)), (KEY, bytes(65))):
            with self.subTest(size=len(data)), self.assertRaises(ValueError):
                recovery.decrypt(key, data)
        with self.assertRaises(ValueError):
            recovery.decode_cbor(cbor2.dumps({}) + b"\x00")
        with self.assertRaises(ValueError):
            recovery.credential_section({"cred": cbor2.dumps(fixture()) + b"\x00"})

    def test_owner_identity_and_nul_are_preserved(self):
        record = saver.select_credential({"cred": cbor2.dumps(fixture())}, TARGET, "synthetic")
        self.assertEqual(record["device_id"], str(TARGET))
        self.assertEqual(record["psk_identity"], str(OWNER))
        self.assertEqual(uuid.UUID(record["psk_identity"]).bytes, OWNER.bytes)
        self.assertEqual(record["psk_hex"], KEY[:16].hex())
        self.assertTrue(record["identity_contains_nul"])
        self.assertIn("pending", record["validation"])

    def test_missing_or_ambiguous_match_rejected(self):
        for count in (0, 2):
            creds = fixture()
            creds["creds"] *= count
            with self.subTest(count=count), self.assertRaises(RuntimeError):
                saver.select_credential({"cred": creds}, TARGET, "synthetic")

    def test_wrong_subject_or_type_rejected(self):
        for field, value in (("subjectuuid", str(OWNER)), ("credtype", 8)):
            creds = fixture()
            creds["creds"][0][field] = value
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                saver.select_credential({"cred": creds}, TARGET, "synthetic")

    def test_private_key_validation(self):
        cases = [("encoding", "raw"), ("data", "not base64!"),
                 ("data", base64.b64encode(b"short").decode())]
        for field, value in cases:
            creds = fixture()
            creds["creds"][0]["privatedata"][field] = value
            with self.subTest(field=field, value=value), self.assertRaises((ValueError, RuntimeError)):
                saver.select_credential({"cred": creds}, TARGET, "synthetic")
        creds = fixture()
        creds["creds"][0]["privatedata"]["data"] = base64.b64encode(KEY).decode()
        self.assertEqual(saver.select_credential({"cred": creds}, TARGET, "synthetic")["psk_hex"], KEY.hex())
        creds["rowneruuid"] = str(uuid.UUID(int=0))
        with self.assertRaises(RuntimeError):
            saver.select_credential({"cred": creds}, TARGET, "synthetic")

    @unittest.skipIf(os.name == "nt", "Windows does not enforce POSIX file modes")
    def test_output_private_and_never_overwritten(self):
        record = saver.select_credential({"cred": fixture()}, TARGET, "synthetic")
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "synthetic.json"
            saver.save_record(output, record)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            self.assertEqual(json.loads(output.read_text()), record)
            with self.assertRaises(FileExistsError):
                saver.save_record(output, {})
            link = Path(directory) / "link.json"
            link.symlink_to(output)
            with self.assertRaises(FileExistsError):
                saver.save_record(link, {})
            self.assertEqual(json.loads(output.read_text()), record)

    def test_read_store_recovers_with_captured_key_and_cleans_up(self):
        adb = FakeAdb(store=encrypted(cbor2.dumps({"cred": cbor2.dumps(fixture())})))
        with patch.object(recovery, "make_adb", return_value=adb):
            with patch.object(recovery.subprocess, "run", return_value=frida_result(KEY)) as frida:
                store, digest = recovery.read_store("synthetic-serial", str(TARGET))
        self.assertEqual(recovery.credential_section(store), fixture())
        self.assertEqual(len(digest), 64)
        self.assertTrue(frida.called)
        self.assertIn(["forward", "--remove", "tcp:45678"], adb.calls)
        self.assertNotIn(["shell", "am", "force-stop", recovery.PACKAGE], adb.calls)

    def test_read_store_spawns_when_attach_yields_nothing(self):
        adb = FakeAdb(store=encrypted(cbor2.dumps({"cred": cbor2.dumps(fixture())})))
        results = [frida_result(), frida_result(KEY)]  # attach empty, then spawn
        with patch.object(recovery, "make_adb", return_value=adb):
            with patch.object(recovery.subprocess, "run", side_effect=results):
                store, _ = recovery.read_store("synthetic-serial", str(TARGET))
        self.assertEqual(recovery.credential_section(store), fixture())
        self.assertIn(["shell", "am", "force-stop", recovery.PACKAGE], adb.calls)

    def test_read_store_tries_every_candidate_key(self):
        adb = FakeAdb(store=encrypted(cbor2.dumps({"cred": cbor2.dumps(fixture())})))
        wrong = bytes([7]) * 32
        with patch.object(recovery, "make_adb", return_value=adb):
            with patch.object(recovery.subprocess, "run", return_value=frida_result(wrong, KEY)):
                store, _ = recovery.read_store("synthetic-serial", str(TARGET))
        self.assertEqual(recovery.credential_section(store), fixture())

    def test_read_store_fails_without_any_key(self):
        adb = FakeAdb(store=encrypted(cbor2.dumps({"cred": cbor2.dumps(fixture())})))
        with patch.object(recovery, "make_adb", return_value=adb):
            with patch.object(recovery.subprocess, "run", return_value=frida_result()):
                with self.assertRaises(RuntimeError):
                    recovery.read_store("synthetic-serial", str(TARGET))

    def test_detect_root_accepts_adb_root_and_su(self):
        self.assertEqual(recovery.detect_root(FakeAdb(shell_is_root=True)), "adbroot")
        self.assertEqual(recovery.detect_root(FakeAdb(shell_is_root=False, su_is_root=True)), "su")
        with self.assertRaises(RuntimeError):
            recovery.detect_root(FakeAdb(shell_is_root=False, su_is_root=False))

    def test_wrong_build_rejected_before_attachment_when_strict(self):
        adb = FakeAdb(version="9.9", code="1")
        with patch.dict(os.environ, {"PSK_STRICT_BUILD": "1"}):
            with patch.object(recovery, "make_adb", return_value=adb):
                with patch.object(recovery.subprocess, "run") as frida:
                    with self.assertRaises(RuntimeError):
                        recovery.read_store("synthetic-serial", str(TARGET))
        frida.assert_not_called()
        self.assertFalse(any(call[0] == "forward" for call in adb.calls))

    def test_unverified_build_proceeds_when_not_strict(self):
        adb = FakeAdb(version="1.8.52.23", code="185223010", abi="x86_64",
                      store=encrypted(cbor2.dumps({"cred": cbor2.dumps(fixture())})))
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("PSK_STRICT_BUILD", None)
            with patch.object(recovery, "make_adb", return_value=adb):
                with patch.object(recovery.subprocess, "run", return_value=frida_result(KEY)):
                    store, _ = recovery.read_store("synthetic-serial", str(TARGET))
        self.assertEqual(recovery.credential_section(store), fixture())

    def test_invalid_store_cannot_reach_root_shell(self):
        with patch.object(recovery, "make_adb") as adb:
            with self.assertRaises(ValueError):
                recovery.read_store("synthetic-serial", "../invalid; command")
            adb.assert_not_called()


if __name__ == "__main__":
    unittest.main()
