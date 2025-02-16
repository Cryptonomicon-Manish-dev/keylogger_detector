import psutil
import ctypes
import os
import platform

try:
    import pygetwindow as gw
except ImportError:
    gw = None  # Only needed for Windows

# List of known keylogger process names (expand as needed)
KNOWN_KEYLOGGERS = ["keylog", "hook", "spy", "logger", "xinput", "winlogon"]

# List of suspicious window titles (Windows only)
SUSPICIOUS_WINDOW_TITLES = ["Keylogger", "Spy", "Monitor", "Stealth"]

# Function to detect suspicious running processes
def detect_suspicious_processes():
    print("\n[🔍] Scanning running processes...")

    for process in psutil.process_iter(attrs=['pid', 'name']):
        process_name = process.info['name'].lower()
        for keyword in KNOWN_KEYLOGGERS:
            if keyword in process_name:
                print(f"[⚠️ ALERT] Suspicious Process Found: {process_name} (PID: {process.info['pid']})")
                terminate_process(process.info['pid'])

# Function to terminate suspicious processes
def terminate_process(pid):
    try:
        os.kill(pid, 9)  # Force kill process
        print(f"[✅] Process {pid} terminated successfully!")
    except Exception as e:
        print(f"[❌] Failed to terminate process {pid}: {e}")

# Function to detect keyboard hooks (Windows only)
def detect_keyboard_hooks():
    if platform.system() != "Windows":
        return  # Keyboard hook detection only works on Windows

    print("\n[🔍] Checking for keyboard hooks...")
    user32 = ctypes.windll.user32
    hooks = user32.GetKeyboardLayoutList(0, None)

    if hooks > 1:
        print("[⚠️ ALERT] Multiple keyboard hooks detected! Possible keylogger active.")
    else:
        print("[✅] No suspicious keyboard hooks found.")

# Function to detect suspicious window titles (Windows only)
def detect_suspicious_windows():
    if gw is None or platform.system() != "Windows":
        return  # Only works on Windows

    print("\n[🔍] Checking for suspicious window titles...")
    windows = gw.getAllTitles()
    
    for title in windows:
        if any(suspicious in title for suspicious in SUSPICIOUS_WINDOW_TITLES):
            print(f"[⚠️ ALERT] Suspicious Window Detected: {title}")

# Main function
def main():
    print("\n🔰 Keylogger Detection Tool 🔰")
    detect_suspicious_processes()
    detect_keyboard_hooks()
    detect_suspicious_windows()
    print("\n[✅] Scan Completed.")

if __name__ == "__main__":
    main()
