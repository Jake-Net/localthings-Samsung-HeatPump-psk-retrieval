// Minimal injection probe. Prints a few facts and exits. No hooks, no secrets.
Java.perform(function () {
  console.log("PROBE arch=" + Process.arch);
  try {
    var ctx = Java.use("android.app.ActivityThread").currentApplication();
    console.log("PROBE package=" + (ctx === null ? "null" : ctx.getPackageName()));
    if (ctx !== null) {
      var prefs = ctx.getSharedPreferences("iotivityKey", 0);
      var v = prefs.getString("iotivityKey", null);
      console.log("PROBE iotivityKey present=" + (v !== null) + " len=" + (v === null ? 0 : String(v).length));
    }
  } catch (e) {
    console.log("PROBE err=" + e);
  }
  console.log("PROBE done");
});
