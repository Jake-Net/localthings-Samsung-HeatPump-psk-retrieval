# Final runbook — Samsung heat-pump OwnerPSK (SM-A217F, Android 12)

Last verified: 2026-10-26
Device: Galaxy A21s `SM-A217F`, Android 12 (SDK 31)
App: SmartThings `1.8.52.23` (`versionCode=185223020`), Galaxy Store
Appliance: Samsung EHS heat pump + Wi-Fi Kit `MIM-H04EN`, `192.168.6.243`

Result: OwnerPSK recovered and accepted by LocalThings in Home Assistant.

Secrets live in `private/heatpump-owner-psk.json` and are deliberately not
repeated in this file.

---

## 1. Root and hide root

1. Unlock the bootloader and root with Magisk 26.3 (stock vbmeta,
   `KEEPVERITY=true KEEPFORCEENCRYPT=true`).
2. Verify:
   ```sh
   adb -s R58NA2KW1TR shell 'su -c id'
   # uid=0(root)
   ```
3. Repackage the Magisk app (Magisk → Settings → Hide the Magisk app).
   Record the new package name.
4. Enable **Zygisk** and **Enforce DenyList**.
5. Add `com.samsung.android.oneconnect` to the DenyList.

## 2. Install and sign in to SmartThings

1. Install SmartThings from **Galaxy Store** (the APKMirror APK is rejected
   by Samsung's cross-download check).
2. Sign in with the account that owns the heat pump.
3. Confirm the **Heat Pump** and **Wi-Fi Kit** appear under Devices.

## 3. Confirm there is no key yet

Login only syncs the cloud device list. Check:

```sh
adb -s R58NA2KW1TR shell 'su -c "find /data -name \"*.datenc\" 2>/dev/null"'
```

If this prints nothing, and the app DB shows
`executionContext: CLOUD`, there is no local OwnerPSK yet.

## 4. Re-onboard the Wi-Fi Kit on the rooted phone

This is what writes the account store.

1. SmartThings → **Devices** → Wi-Fi Kit → **⋮** → **Remove device**.
   Remove the Heat Pump too if it remains.
2. On the Wi-Fi Kit, hold the **AP button ~5 s** until the Wi-Fi setup LED
   turns on.
3. SmartThings → **+** → **Add device** → **Scan nearby**.
4. Connect to the kit's AP, enter the local Wi-Fi password.
5. Finish onboarding until the heat pump is online.

After this, a store appears:

```text
/data/user/0/com.samsung.android.oneconnect/files/<STORE_UUID>.datenc
/data/user/0/com.samsung.android.oneconnect/files/<STORE_UUID>.dat
/data/user/0/com.samsung.android.oneconnect/files/<STORE_UUID>.db
```

Observed: `af4e1631-66ed-3726-ad65-xxxxxxxxxxxx`.

## 5. Do not rely on Frida's Java bridge

Frida 16.7.19 and 17.24.2 both fail on this Samsung Android 12 build:

```text
Unable to determine ClassLinker field offsets
```

This is an upstream Android-12 issue, not a setup mistake. Use the native
route below instead.

## 6. Find the storage key in native memory

The main SmartThings process loads `liboctbstack.so` and holds the 32-byte
storage key in the library's writable data segment.

1. Start the phone's Frida server (17.24.2 or 16.7.19 both work for native
   hooks), forward the port, and read the module base:
   ```js
   var m = Process.getModuleByName('liboctbstack.so');
   console.log(m.base, m.size);
   ```
2. In `/proc/<pid>/maps`, find the `rw-p` mappings belonging to that module
   (they follow the `r-xp` mappings). Typically 4 KB `.data` + 4 KB `.bss`.
3. Dump that region as root:
   ```sh
   su -c 'dd if=/proc/<pid>/mem of=/sdcard/octb.bin bs=4096 skip=<addr/4096> count=2'
   ```
4. Pull `octb.bin` and the current `.datenc`.
5. Scan every 32-byte window for the value whose
   `HMAC-SHA256(candidate, ciphertext)` equals the store's trailing 32-byte MAC.
   The matching window is the storage key.

`decrypt_store.py` in this directory contains the decryption half of the
check and can be extended to report the match.

## 7. Decrypt the store and extract the PSK

`.datenc` layout:

```text
16-byte IV | AES-256-CBC ciphertext | 32-byte HMAC-SHA256
HMAC key   = the same 32-byte storage key
HMAC input = ciphertext only
plain size = file size - 64 + (IV[15] & 0x0f)
```

Run:

```sh
python decrypt_store.py <store>.datenc <storage-key-hex> private/heatpump-owner-psk.json
```

The script verifies the MAC, decodes the CBOR, and picks the single
`credtype=1` credential.

Observed result:

```text
subject (device)  fd41c401-3203-099c-d27c-xxxxxxxxxxxx   (Wi-Fi Kit)
owner  (identity) debaee55-70a7-8239-be5a-xxxxxxxxxxxx
key length        16 bytes
identity NUL?     no
```

The subject is the **Wi-Fi Kit**, because that is the DTLS endpoint; the heat-pump child device sits behind it.

## 8. Configure LocalThings

Home Assistant → **Settings → Devices & Services → Add Integration →
LocalThings**.

| Field | Value |
|---|---|
| IP | `x.x.x` |
| Credential type | Owner PSK |
| Identity | `private/heatpump-owner-psk.json` → `psk_identity` |
| PSK | `private/heatpump-owner-psk.json` → `psk_hex` |
| OCF device ID (if asked) | `fd41c401-3203-099c-d27c-xxxxxxxxxxxx` |

Do not paste the storage key or the store UUID into the identity field.

Because the identity contains no zero byte, the upstream Mbed TLS patch for
OpenSSL NUL-containing identities is **not** required.

## 9. Cleanup

1. Stop `frida-server` and remove `/data/local/tmp/frida-server*`.
2. Delete `/sdcard/octb.bin`, `.datenc` copies, screenshots, and UI dumps.
3. Keep `private/heatpump-owner-psk.json` off Git and off shared folders.

## Notes and gotchas

- Login alone never creates `.datenc`; only local onboarding does.
- `oic_svr_db_client.dat` can have 0 credentials and still be normal.
- The `.dat` companion is plaintext and holds only trust certificates.
- The `.db` companion records OTM state; it does not contain the PSK.
- An Android 12 host test over a different subnet may time out because UDP
  5684 is not routed; Home Assistant on the same LAN is fine.
- `psiIsKeySet()` is 1 only in the process that performed the onboarding.
  Read it before restarting SmartThings.
