'use strict';

console.log("[Frida] Script loading started...");

// Simple exports that work immediately without Java
// Using lowercase names to match Frida's automatic conversion
var rpc_exports = {
  clearvulnerabilities: function() {
    console.log("[Frida] clearvulnerabilities called");
    return true;
  },

  getcurrentactivity: function() {
    console.log("[Frida] getcurrentactivity called successfully!");
    // Return a known TikTok activity for now
    return "com.ss.android.ugc.aweme.splash.SplashActivity";
  },

  callwebviewloadurl: function(url) {
    console.log("[Frida] callwebviewloadurl called with: " + url);
    return true;
  }
};

console.log("[Frida] Script loading completed");
rpc.exports = rpc_exports;