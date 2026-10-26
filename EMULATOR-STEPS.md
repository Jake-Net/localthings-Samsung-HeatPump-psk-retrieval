# PSK recovery on your emulator (FridaDebug, x86_64, Android 14)

These are the upstream research scripts (`KRZ303/locathings-oven-psk-retrieval`),
edited so they can run against **your** target instead of a rooted arm64 phone:

| Asset | Change |
| --- | --- |
| emulator | AVD `FridaDebug`, x86_64, Android 14 (`google_apis`) |
| app | SmartThings `1.8.52.23` (185223010), ARM-only APK under `ndk_translation` |
| frida-server | `frida-server-17.24.2-android-x86_64` |
| host | `pip install -r requirements-emulator.txt` (frida 17.24.2) |

## What was changed and why

* **`read-storage-key.js` — build-agnostic capture.** The upstream agent called
  R8-obfuscated names specific to build `1.8.51.30`. Your build is `1.8.52.23`,
  so those names may not exist. The agent now finds the 32-byte IoTivity storage
  key *by behaviour* (Base64 decode, `SecretKeySpec` construction) and keeps the
  old named path only as a fast lane.
* **`inspect_encrypted_store.py` — target checks relaxed, root auto-detected.**
  The hard arm64-only check would have failed on x86_64; it is now a note. The
  exact-build check is a warning (set `PSK_STRICT_BUILD=1` to make it fatal
  again). Root comes from `adb root` (adbd already uid 0) or from `su`, whichever
  the device offers.
* **Multiple candidate keys.** Behavioural capture can yield more than one
  32-byte buffer, so every candidate is tried against the store's HMAC-SHA256
  until one authenticates. A wrong key fails the MAC and is skipped, so the
  result is still exactly one verified credential.
* **Spawn fallback.** If nothing is captured while attached (the app already read
  its key at startup), SmartThings is force-stopped and re-launched under Frida
  so the startup decryption is caught.
* **`test_recovery.py`** was updated to the new contract. `python -m unittest
  test_recovery` prints `OK`. The file-mode test is skipped on Windows because
  Windows does not enforce POSIX `0600`.

## Procedure

### 1. Boot the emulator and get root
```
& "C:\Users\kelly\.android\studio\SDK\emulator\emulator.exe" -avd FridaDebug
adb wait-for-device
adb root              # adbd restarts as uid 0
adb wait-for-device
```

### 2. Run the x86_64 Frida server
```
adb push "C:\Users\kelly\Downloads\frida-server-17.24.2-android-x86_64" /data/local/tmp/frida-server
adb shell chmod 700 /data/local/tmp/frida-server
adb shell "nohup /data/local/tmp/frida-server -l 127.0.0.1:27042 >/dev/null 2>&1 &"
```
Leave it running. The host helper opens and removes its own `adb forward`.

### 3. Install and register SmartThings
```
adb install "C:\Users\kelly\Downloads\com.samsung.android.oneconnect_1.8.52.23-185223010_minAPI31(arm64-v8a,armeabi-v7a)(nodpi)_apkmirror.com.apk"
```
Open SmartThings, sign in with the Samsung account, and **register the heat pump**.
The `.datenc` credential store only exists once the appliance is registered on
*this* emulator with *this* account.

### 4. Confirm capture works before hunting the store
```
cd "C:\Users\kelly\Documents\Default Project\psk-retrieval"
.venv\Scripts\python.exe inspect_encrypted_store.py --serial emulator-5554 \
  --store 00000000-0000-0000-0000-000000000000 --capture-only
```
`--store` is ignored in this mode; you only want `Candidate recovery keys
captured: 1` (or more). If it is `0`, the behavioural hooks need extending —
tell me and I will add `Cipher`/`CryptoManager` hooks.

### 5. Find the account store
```
adb shell "find /data/user/0/com.samsung.android.oneconnect/files -maxdepth 1 -type f -name '*.datenc'"
```
Set `STORE_UUID` to one filename without its extension, then inspect it:
```
set STORE_UUID=<uuid>
.venv\Scripts\python.exe inspect_encrypted_store.py --serial emulator-5554 --store %STORE_UUID%
.venv\Scripts\python.exe inspect_encrypted_store.py --serial emulator-5554 --store %STORE_UUID% --show-identifiers
```
`--show-identifiers` prints the text **not** the key. Keep it private.

### 6. Get the appliance OCF UUID to match the credential subject
The companion `files/<uuid>.db` lists it (using the venv's Python, so no
`sqlite3` CLI needed):
```
adb shell "cat /data/user/0/com.samsung.android.oneconnect/files/<uuid>.db" > private\store.db
.venv\Scripts\python.exe -c "import sqlite3;print([r[0] for r in sqlite3.connect(r'private\store.db').execute('select UUID from T_DEVICE_LIST')])"
```
The value that matches a `PSK subject` from step 5 is the appliance OCF UUID.

### 7. Save the credential
```
.venv\Scripts\python.exe save-oven-key.py --serial emulator-5554 \
  --store %STORE_UUID% --device-uuid <appliance-ocf-uuid> \
  --output private\owner-psk.json
```
Then import `psk_identity` + `psk_hex` into LocalThings as an **owner PSK**,
using the heat pump's LAN IP.

## Honest limits

* The behavioural capture is **unverified on your exact build**; I could not run
  it without your emulator. Step 4 is the gate — if it captures a key, the rest
  is deterministic; if not, the hooks need extending.
* `private\owner-psk.json` is a **usable secret**. Windows does not enforce the
  `0600` mode, so protect the folder another way and never commit it.
* This assumes the heat pump can be registered in SmartThings on the emulator.
  If sign-in or registration fails there, the emulator route is a dead end and a
  rooted physical phone is the tested path.
* Use only with an appliance, account and phone you own or are authorised to
  inspect.
