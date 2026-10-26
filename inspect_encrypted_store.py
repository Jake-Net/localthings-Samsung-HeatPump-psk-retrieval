"""Read an existing SmartThings store; verify its ciphertext MAC before decoding.

Adapted for a rooted x86_64 emulator (ARM app under ndk_translation) and for
SmartThings builds other than the one the upstream research targeted:

* root is obtained from ``adb root`` (adbd already uid 0) or from ``su``,
  auto-detected;
* the exact-build guard is a warning by default (set PSK_STRICT_BUILD=1 to make
  it fatal again);
* the storage key is recovered by behaviour, so several candidates may be
  captured; each is tried against the store's HMAC until one verifies.
"""
import argparse
import base64
import hashlib
import hmac
import io
import os
import pathlib
import re
import shlex
import subprocess
import uuid

import cbor2
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ROOT = pathlib.Path(__file__).resolve().parent
PACKAGE = "com.samsung.android.oneconnect"
AGENT = ROOT / "read-storage-key.js"

# Build the upstream research verified. Other builds are allowed but warned
# about, because recovery is version-sensitive.
REFERENCE_VERSION_NAME = "1.8.51.30"
REFERENCE_VERSION_CODE = 185130010

# Quiet-mode windows (seconds) the Frida CLI stays attached while the agent runs.
ATTACH_SECONDS = 8
SPAWN_SECONDS = 25


def decrypt(key, data):
    # Layout verified against psiDecrypt in this app's ARM64 liboctbstack.so.
    if len(key) != 32 or len(data) < 64 or len(data) % 16:
        raise ValueError("Invalid encrypted store size")
    iv, ciphertext, mac = data[:16], data[16:-32], data[-32:]
    if not hmac.compare_digest(hmac.digest(key, ciphertext, "sha256"), mac):
        raise ValueError("Encrypted store authentication failed")
    decoder = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = decoder.update(ciphertext) + decoder.finalize()
    size = len(data) - 64 + (iv[15] & 15)
    return padded[:size]


def selftest():
    key = bytes(range(32))
    for size in (1, 15, 16, 17, 32, 129):
        plain = b"x" * size
        iv = bytes(15) + bytes([size & 15])
        padded = plain + bytes(16 - size % 16)
        encoder = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        ciphertext = encoder.update(padded) + encoder.finalize()
        data = iv + ciphertext + hmac.digest(key, ciphertext, "sha256")
        assert decrypt(key, data) == plain
        try:
            decrypt(key, data[:-1] + bytes([data[-1] ^ 1]))
        except ValueError:
            pass
        else:
            raise AssertionError("Corrupted authentication tag was accepted")


def decode_cbor(data):
    stream = io.BytesIO(data)
    result = cbor2.CBORDecoder(stream).decode()
    if stream.read():
        raise ValueError("Unexpected trailing CBOR data")
    return result


def credential_section(store):
    value = store["cred"]
    return decode_cbor(value) if isinstance(value, bytes) else value


def make_adb(serial):
    def adb(*args):
        return subprocess.check_output(
            ["adb", "-s", serial, *args], stderr=subprocess.PIPE, timeout=30
        )
    return adb


def detect_root(adb):
    """Return 'adbroot' if adbd is already root, else 'su' if su works."""
    try:
        if b"uid=0" in adb("shell", "id"):
            return "adbroot"
    except Exception:
        pass
    try:
        if b"uid=0" in adb("exec-out", shlex.join(["su", "-c", "id"])):
            return "su"
    except Exception:
        pass
    raise RuntimeError(
        "Root is required. Run 'adb root' first, or grant su to the adb shell.")


def make_root(adb, mode):
    if mode == "adbroot":
        def root(command):
            return adb("exec-out", "sh", "-c", command)
    else:
        def root(command):
            return adb("exec-out", shlex.join(["su", "-c", command]))
    return root


def check_target(adb):
    """Warn (or, with PSK_STRICT_BUILD=1, fail) on an unverified target."""
    strict = os.environ.get("PSK_STRICT_BUILD") == "1"
    try:
        info = adb("shell", "dumpsys", "package", PACKAGE).decode("utf-8", "replace")
    except Exception:
        raise RuntimeError("Could not read package info; is SmartThings installed?")
    if PACKAGE not in info:
        raise RuntimeError(f"{PACKAGE} is not installed on this device")

    match = re.search(r"\bversionName=(\S+)", info)
    vname = match.group(1) if match else "?"
    match = re.search(r"\bversionCode=(\d+)", info)
    vcode = match.group(1) if match else "?"
    try:
        abi = adb("shell", "getprop", "ro.product.cpu.abi").decode().strip()
    except Exception:
        abi = "?"

    problems = []
    if vname != REFERENCE_VERSION_NAME or vcode != str(REFERENCE_VERSION_CODE):
        problems.append(
            f"SmartThings {vname} ({vcode}) differs from the verified "
            f"{REFERENCE_VERSION_NAME} ({REFERENCE_VERSION_CODE})")
    if abi == "x86_64":
        print("NOTE: ARM app detected; it runs through ndk_translation. "
              "Java-level capture is unaffected.")
    elif abi != "arm64-v8a":
        problems.append(f"unexpected ABI {abi}")

    if problems:
        if strict:
            raise RuntimeError("Unsupported target: " + "; ".join(problems))
        print("WARNING: " + "; ".join(problems))
        print("WARNING: relying on the build-agnostic capture path; the named "
              "fast lane may not apply.")


def _capture_keys(adb, frida, spawn):
    port = adb("forward", "tcp:0", "tcp:27042").decode().strip()
    try:
        args = [frida, "-H", "127.0.0.1:" + port, "-q", "-l", str(AGENT)]
        if spawn:
            args += ["-f", PACKAGE, "-t", str(SPAWN_SECONDS), "--kill-on-exit"]
        else:
            pid = adb("shell", "pidof", PACKAGE).decode().strip()
            if not pid:
                return []
            args += ["-p", pid.split()[0], "-t", str(ATTACH_SECONDS)]
        result = subprocess.run(
            args, capture_output=True, text=True, timeout=SPAWN_SECONDS + 40,
            stdin=subprocess.DEVNULL)
        keys = []
        for line in result.stdout.splitlines():
            if line.startswith("RECOVERY_KEY:"):
                keys.append(base64.b64decode(
                    line[len("RECOVERY_KEY:"):].strip(), validate=True))
        return keys
    finally:
        try:
            adb("forward", "--remove", "tcp:" + port)
        except Exception:
            pass


def recover_keys(adb, frida="frida"):
    """Capture candidate storage keys, attaching first and spawning as fallback."""
    keys = []
    try:
        keys += _capture_keys(adb, frida, spawn=False)
    except Exception:
        pass
    if not keys:
        print("No key while attached; re-launching SmartThings to capture startup.")
        try:
            adb("shell", "am", "force-stop", PACKAGE)
        except Exception:
            pass
        try:
            keys += _capture_keys(adb, frida, spawn=True)
        except Exception:
            pass
    seen, ordered = set(), []
    for key in keys:
        if key not in seen:
            seen.add(key)
            ordered.append(key)
    return ordered


def read_store(serial, store_id, frida="frida"):
    # A canonical UUID prevents paths or shell syntax entering the root command.
    store_id = str(uuid.UUID(store_id))
    adb = make_adb(serial)
    mode = detect_root(adb)
    root = make_root(adb, mode)
    check_target(adb)

    data = root(f"cat /data/user/0/{PACKAGE}/files/{store_id}.datenc")
    if not data:
        raise RuntimeError("Store file is empty or missing")
    digest = hashlib.sha256(data).hexdigest()

    keys = recover_keys(adb, frida)
    if not keys:
        raise RuntimeError(
            "No candidate recovery key captured. Open SmartThings and sign in, "
            "then retry; if it still fails the app build is not recoverable by "
            "behaviour alone.")
    for key in keys:
        try:
            store = decode_cbor(decrypt(key, data))
        except Exception:
            continue
        return store, digest
    raise RuntimeError(
        "Recovered %d candidate key(s) but none authenticated the store "
        "(wrong account/build, or the appliance is not registered here)." % len(keys))


def connection_arguments(parser):
    parser.add_argument("--serial", required=True, help="ADB serial of your rooted device")
    parser.add_argument("--store", required=True, type=uuid.UUID, help="Account store UUID, without .datenc")
    parser.add_argument("--frida", default="frida", help="Frida CLI executable from the prepared environment")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    connection_arguments(parser)
    parser.add_argument("--show-identifiers", action="store_true", help="Print private owner and PSK subject UUIDs, never keys")
    parser.add_argument("--capture-only", action="store_true", help="Only report how many candidate keys the agent captures")
    args = parser.parse_args()

    selftest()
    adb = make_adb(args.serial)
    if args.capture_only:
        keys = recover_keys(adb, args.frida)
        print("Candidate recovery keys captured:", len(keys))
        return
    store, _ = read_store(args.serial, str(args.store), args.frida)
    creds = credential_section(store)
    entries = creds.get("creds", [])
    print("PASS: ciphertext MAC and complete CBOR decoding verified")
    print("Credential count:", len(entries))
    print("PSK count:", sum(c.get("credtype") == 1 for c in entries))
    if args.show_identifiers:
        print("Credential owner:", str(uuid.UUID(creds["rowneruuid"])))
        for cred in entries:
            if cred.get("credtype") == 1:
                print("PSK subject:", str(uuid.UUID(cred["subjectuuid"])))


if __name__ == "__main__":
    main()
