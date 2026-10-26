// Diagnostic only: report what is visible in the target process. No secrets.
function tag(name, ok) { console.log("DIAG " + name + ": " + ok); }

Java.perform(function () {
  tag("arch", Process.arch);
  tag("frida", Frida.version);

  var ctx = null;
  try {
    ctx = Java.use("android.app.ActivityThread").currentApplication();
  } catch (e) { tag("ActivityThread", "ERR " + e); }
  tag("context", ctx === null ? "null" : String(ctx));
  if (ctx !== null) tag("package", ctx.getPackageName());

  tag("class sk.b", (function () { try { Java.use("sk.b"); return true; } catch (e) { return false; } })());
  tag("class ...oneconnect.f4", (function () { try { Java.use("com.samsung.android.oneconnect.f4"); return true; } catch (e) { return false; } })());

  var counts = { b64str: 0, b64bytes: 0, b64range: 0, sks: 0 };
  var hits = { b64: 0, sks: 0 };

  try {
    var B64 = Java.use("android.util.Base64");
    try {
      var d1 = B64.decode.overload("java.lang.String", "int");
      d1.implementation = function (a, b) { var r = d1.call(this, a, b); counts.b64str++; if (r && r.length === 32) hits.b64++; return r; };
    } catch (e) { tag("hook b64(String,int)", "ERR"); }
    try {
      var d2 = B64.decode.overload("[B", "int");
      d2.implementation = function (a, b) { var r = d2.call(this, a, b); counts.b64bytes++; if (r && r.length === 32) hits.b64++; return r; };
    } catch (e) { tag("hook b64([B,int)", "ERR"); }
    try {
      var d3 = B64.decode.overload("[B", "int", "int", "int");
      d3.implementation = function (a, b, c, d) { var r = d3.call(this, a, b, c, d); counts.b64range++; if (r && r.length === 32) hits.b64++; return r; };
    } catch (e) { tag("hook b64(range)", "ERR"); }
    tag("Base64", "hooked");
  } catch (e) { tag("Base64", "ERR " + e); }

  try {
    var SKS = Java.use("javax.crypto.spec.SecretKeySpec");
    var s2 = SKS.$init.overload("[B", "java.lang.String");
    s2.implementation = function (k, a) { counts.sks++; if (k && k.length === 32) hits.sks++; return s2.call(this, k, a); };
    tag("SecretKeySpec", "hooked");
  } catch (e) { tag("SecretKeySpec", "ERR " + e); }

  // Is the iotivityKey preference present at all?
  try {
    var p = ctx.getSharedPreferences("iotivityKey", 0);
    var v = p.getString("iotivityKey", null);
    tag("pref iotivityKey present", v !== null);
    if (v !== null) tag("pref length", String(v).length);
  } catch (e) { tag("pref", "ERR " + e); }

  setTimeout(function () {
    console.log("DIAG counts " + JSON.stringify(counts));
    console.log("DIAG hits " + JSON.stringify(hits));
  }, 6000);
});
