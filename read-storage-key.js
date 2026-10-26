// SmartThings IoTivity storage-key reader.
//
// Build-agnostic: unlike the upstream agent, this does not rely on the
// R8-obfuscated class/method names (sk.b, com.samsung.android.oneconnect.f4,
// X(), manager.b). It watches the Java layer for the 32-byte IoTivity storage
// key wherever it appears, so it works across app builds and CPU architectures
// (including an ARM app running through ndk_translation on an x86_64 emulator).
//
// The named path is still attempted as a fast lane; on any other build it
// simply fails silently and the generic capture takes over.
//
// The RECOVERY_KEY message is SECRET. Never log this agent's raw output.
// Read only the existing IoTivity storage key. Never generate or replace a key.
Java.perform(function () {
  var KEY = "RECOVERY_KEY:";
  var emitted = {};

  function emit(bytes) {
    try {
      if (bytes === null || bytes.length !== 32) return;
      var B64 = Java.use("android.util.Base64");
      var enc = B64.encodeToString(bytes, 2); // 2 == NO_WRAP
      if (!emitted[enc]) {
        emitted[enc] = true;
        console.log(KEY + enc);
      }
    } catch (e) {
      // Never surface arbitrary Java exceptions: they could carry private data.
    }
  }

  // --- Generic path 1: the key is a 32-byte Base64-decoded buffer. ---
  (function () {
    var B64;
    try { B64 = Java.use("android.util.Base64"); } catch (e) { return; }

    try {
      var decodeString = B64.decode.overload("java.lang.String", "int");
      decodeString.implementation = function (data, flags) {
        var result = decodeString.call(this, data, flags);
        emit(result);
        return result;
      };
    } catch (e) {}

    try {
      var decodeBytes = B64.decode.overload("[B", "int");
      decodeBytes.implementation = function (data, flags) {
        var result = decodeBytes.call(this, data, flags);
        emit(result);
        return result;
      };
    } catch (e) {}

    try {
      var decodeRange = B64.decode.overload("[B", "int", "int", "int");
      decodeRange.implementation = function (data, offset, length, flags) {
        var result = decodeRange.call(this, data, offset, length, flags);
        emit(result);
        return result;
      };
    } catch (e) {}
  })();

  // --- Generic path 2: the key becomes an AES/HMAC SecretKeySpec. ---
  (function () {
    var SKS;
    try { SKS = Java.use("javax.crypto.spec.SecretKeySpec"); } catch (e) { return; }

    try {
      var init2 = SKS.$init.overload("[B", "java.lang.String");
      init2.implementation = function (key, algorithm) {
        emit(key);
        return init2.call(this, key, algorithm);
      };
    } catch (e) {}

    try {
      var init4 = SKS.$init.overload("[B", "int", "int", "java.lang.String");
      init4.implementation = function (key, offset, length, algorithm) {
        try {
          if (length === 32) {
            var window = Java.array("byte", new Array(length).fill(0));
            for (var i = 0; i < length; i++) window[i] = key[offset + i];
            emit(window);
          }
        } catch (e) {}
        return init4.call(this, key, offset, length, algorithm);
      };
    } catch (e) {}
  })();

  // --- Fast lane: original upstream path for the studied build. ---
  (function () {
    try {
      var context = Java.use("android.app.ActivityThread").currentApplication();
      if (context === null) return;
      var component = Java.cast(Java.use("sk.b").a(context),
        Java.use("com.samsung.android.oneconnect.f4"));
      var manager = component.X();
      if (manager.b.value === null) return;
      var wrapped = context.getSharedPreferences("iotivityKey", 0)
        .getString("iotivityKey", null);
      if (wrapped === null || String(wrapped).indexOf(":v1:") !== 0) return;
      var encoded = manager.a.overload("java.lang.String").call(manager, wrapped);
      emit(Java.use("android.util.Base64").decode(encoded, 0));
    } catch (e) {
      // Names differ on this build; the generic paths above still cover it.
    }
  })();
});
