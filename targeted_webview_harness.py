"""
Author: ronaldon2023@gmail.com
"""

#!/usr/bin/env python3
"""
Frida-Enhanced Fuzzing Harness
This script uses Frida for dynamic analysis and runtime testing of vulnerabilities
"""

import sys
import subprocess
import time
import os
import re
import signal
import json
import frida
import threading
from datetime import datetime

# Target app information
TARGET_PACKAGE = "com.ss.android.ugc.trill"
TARGET_ACTIVITY = "com.ss.android.ugc.aweme.main.MainActivity"

# Fix PATH to include Android SDK platform-tools
def setup_android_path():
    """Setup Android SDK path for adb access"""
    android_home = os.path.expanduser("~/Library/Android/sdk")
    platform_tools = os.path.join(android_home, "platform-tools")
    
    if os.path.exists(platform_tools):
        if platform_tools not in os.environ.get("PATH", ""):
            os.environ["PATH"] = f"{platform_tools}:{os.environ.get('PATH', '')}"
            print(f"✅ Added Android SDK platform-tools to PATH: {platform_tools}", file=sys.stderr)
        return platform_tools
    else:
        print(f"⚠️ Android SDK platform-tools not found at: {platform_tools}", file=sys.stderr)
        return None

# Setup Android path at import time
ADB_PATH = setup_android_path()

# Also accept these activities as valid (TikTok has multiple entry points)
VALID_TIKTOK_ACTIVITIES = [
    "com.ss.android.ugc.aweme.main.MainActivity",
    "com.bytedance.pumbaa.offline.base.dialog.PumbaaOfflineDialog",
    "com.ss.android.ugc.aweme.main.MainActivityAlias",
    "com.ss.android.ugc.aweme.splash.SplashActivity"
]

class FridaWebViewFuzzer:
    def __init__(self):
        self.device = None
        self.session = None
        self.script = None
        
    def check_current_activity_frida(self):
        """Check current activity using Frida"""
        try:
            if not self.session or not self.script:
                return None

            # Use the correct, synchronous exports property
            # And the correct method name
            activity_name = self.script.exports_sync.getcurrentactivity()
            return activity_name
        except Exception as e:
            print(f"⚠️ Failed to check current activity via Frida: {e}", file=sys.stderr)
            return None

    def wait_for_main_activity(self, timeout=30):
        """Waits for the main activity to be loaded and ready for fuzzing."""
        print("⏳ Waiting for main activity to load...", file=sys.stderr)
        try:
            start_time = time.time()
            while time.time() - start_time < timeout:
                current_activity = self.script.exports_sync.getcurrentactivity()
                if current_activity in VALID_TIKTOK_ACTIVITIES:
                    print("✅ Target activity is loaded.", file=sys.stderr)
                    return True
                
                print(f"⏳ Current activity: {current_activity or 'unknown'}, waiting...", file=sys.stderr)
                time.sleep(1)
            print("❌ Timeout waiting for main activity to be ready.", file=sys.stderr)
            return False
        except Exception as e:
            print(f"❌ Failed to wait for main activity: {e}", file=sys.stderr)
            return False

    def connect_to_device(self):
        try:
            self.device = frida.get_usb_device()
            print(f"✅ Connected to USB device: {self.device.name}", file=sys.stderr)
            return True
        except frida.InvalidArgumentError:
            try:
                self.device = frida.get_remote_device()
                print(f"✅ Connected to remote device: {self.device.name}", file=sys.stderr)
                return True
            except frida.InvalidArgumentError:
                print("❌ No USB or remote device available", file=sys.stderr)
                return False

    def attach_to_app(self):
        """Attach Frida to the target app"""
        try:
            # First try to find the process by checking if it's running
            adb_cmd = ADB_PATH + "/adb" if ADB_PATH else "adb"
            result = subprocess.run([
                adb_cmd, 'shell', 'ps | grep', TARGET_PACKAGE
            ], capture_output=True, timeout=5)
            
            if result.returncode == 0 and TARGET_PACKAGE in result.stdout.decode():
                # Process is running, try to attach by PID
                try:
                    # Get the PID from the ps output
                    output = result.stdout.decode()
                    for line in output.split('\n'):
                        if TARGET_PACKAGE in line:
                            parts = line.split()
                            if len(parts) >= 2:
                                pid = int(parts[1])
                                print(f"✅ Found running process: {TARGET_PACKAGE} (PID: {pid})", file=sys.stderr)
                                self.session = self.device.attach(pid)
                                print(f"✅ Attached to app process", file=sys.stderr)
                                return True
                except Exception as e:
                    print(f"⚠️ Failed to attach to existing process: {e}", file=sys.stderr)
            
            # If we get here, spawn a new process
            print(f"⚠️ App {TARGET_PACKAGE} not running, attempting to spawn", file=sys.stderr)
            pid = self.device.spawn([TARGET_PACKAGE])
            self.device.resume(pid)
            time.sleep(2)  # Wait for app to start
            self.session = self.device.attach(pid)
            
            print(f"✅ Attached to app process", file=sys.stderr)
            return True
            
        except Exception as e:
            print(f"❌ Failed to attach to app: {e}", file=sys.stderr)
            return False 

    def load_frida_script(self):
        try:
            with open("frida_hooks.js", "r") as f:
                frida_script = f.read()
        except FileNotFoundError:
            print("❌ Frida hooks script not found", file=sys.stderr)
            return False
            
        try:
            self.script = self.session.create_script(frida_script)
            self.script.on('message', self.on_frida_message)
            self.script.load()
            print("✅ Frida script loaded successfully", file=sys.stderr)
            return True
        except Exception as e:
            print(f"❌ Failed to load Frida script: {e}", file=sys.stderr)
            return False
    
    def on_frida_message(self, message, data):
        if message['type'] == 'send':
            print(f"[Frida] {message['payload']}", file=sys.stderr)
        elif message['type'] == 'error':
            print(f"[Frida Error] {message['stack']}", file=sys.stderr)

    def is_attached(self):
        try:
            if self.session and self.session.is_detached:
                return False
            return self.session is not None
        except frida.core.SessionNotFoundError:
            return False

    def test_with_frida(self, input_str):
        try:
            if not self.is_attached():
                print("❌ Frida session detached, attempting to re-attach...", file=sys.stderr)
                self.attach_to_app()
                
                if not self.is_attached():
                    print("❌ Failed to re-attach, propagating crash.", file=sys.stderr)
                    sys.exit(1)

            self.script.exports_sync.clearvulnerabilities()
            self.script.exports_sync.callwebviewloadurl(input_str)

            app_is_attached = self.is_attached()
            if not app_is_attached:
                print("💥 App crashed during WebView.loadUrl test, propagating crash.", file=sys.stderr)
                sys.exit(1)

            return { 'frida_crash_detected': not app_is_attached }
            
        except Exception as e:
            print(f"❌ TARGETED Frida test failed: {e}", file=sys.stderr)
            sys.exit(1)
    
    def cleanup(self):
        """Clean up Frida resources"""
        try:
            if self.script:
                self.script.unload()
            if self.session:
                self.session.detach()
            print("✅ Frida resources cleaned up", file=sys.stderr)
        except Exception as e:
            print(f"⚠️ Cleanup warning: {e}", file=sys.stderr)

def main():
    # Handle both command line arguments (for testing) and stdin (for AFL++)
    if len(sys.argv) > 1:
        # Command line argument mode (for testing)
        input_str = sys.argv[1]
        print(f"🔍 Testing with command line input: {input_str[:100]}...", file=sys.stderr)
    else:
        # AFL++ mode - read from stdin
        try:
            input_data = sys.stdin.buffer.read()
            input_str = input_data.decode('utf-8', errors='ignore')
            print(f"🔍 Processing input from AFL++: {input_str[:100]}...", file=sys.stderr)
        except Exception as e:
            print(f"❌ Failed to read input: {e}", file=sys.stderr)
            sys.exit(1)
    
    # Setup the ADB path
    if not ADB_PATH:
        print("❌ ADB not found, exiting.", file=sys.stderr)
        sys.exit(1)
    
    fuzzer = FridaWebViewFuzzer()
    
    try:
        if not fuzzer.connect_to_device():
            sys.exit(1)
        
        if not fuzzer.attach_to_app():
            sys.exit(1)
            
        if not fuzzer.load_frida_script():
            sys.exit(1)
        
        if not fuzzer.wait_for_main_activity():
            sys.exit(1)
        
        result = fuzzer.test_with_frida(input_str)
        
        if result.get('frida_crash_detected'):
            print("🚨 CRASH DETECTED - Exiting with error code", file=sys.stderr)
            sys.exit(1)
            
        print("✅ Fuzzing completed successfully", file=sys.stderr)
        
    except Exception as e:
        print(f"❌ Fuzzing failed: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        fuzzer.cleanup()

if __name__ == "__main__":
    sys.exit(main())