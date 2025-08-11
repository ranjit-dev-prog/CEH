import os
import datetime
import subprocess
import threading
import time
from pynput import keyboard
import tkinter as tk
import sys

# -------- Hardware Diagnostic Functions --------

def run_powershell(cmd):
    try:
        completed = subprocess.run(
            ["powershell", "-Command", cmd],
            capture_output=True,
            text=True,
            timeout=30,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        if completed.returncode == 0:
            return completed.stdout.strip()
        else:
            return f"Error: {completed.stderr.strip()}"
    except Exception as e:
        return f"Exception: {str(e)}"

def save_results(text, filename="hardware_test_result.txt"):
    desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
    file_path = os.path.join(desktop_path, filename)
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(text)
    print(f"[+] Results saved to {file_path}")

key_log = []
keylog_lock = threading.Lock()

def on_press(key):
    try:
        with keylog_lock:
            key_log.append(f"Key '{key.char}' pressed")
    except AttributeError:
        with keylog_lock:
            key_log.append(f"Special Key '{key}' pressed")

def start_keylogger(duration=15):
    print(f"[*] Keyboard test started. Please press various keys for {duration} seconds...")

    listener = keyboard.Listener(on_press=on_press)
    listener.start()

    # Use threading event to wait for duration seconds without blocking main thread
    stop_event = threading.Event()
    stop_event.wait(duration)

    listener.stop()
    print("[*] Keyboard test completed.")

def save_keylog():
    desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
    file_path = os.path.join(desktop_path, "keyboard_log.txt")
    with keylog_lock:
        log_copy = list(key_log)  # Copy safely
    with open(file_path, "w", encoding="utf-8") as f:
        f.write("\n".join(log_copy))
    print(f"[+] Keyboard log saved to {file_path}")

def display_test():
    print("[*] Starting display test. Watch the screen colors carefully.")
    colors = ["red", "green", "blue", "white", "black"]
    root = tk.Tk()
    root.attributes("-fullscreen", True)
    root.configure(background="black")
    root.focus_set()

    for color in colors:
        root.configure(background=color)
        root.update()
        print(f"Displaying {color} screen. Look for dead pixels or color issues.")
        time.sleep(5)

    root.destroy()
    input("Display test finished. Did you notice any dead pixels or display issues? (Press Enter to continue) ")

def cpu_stress_worker(end_time):
    while time.time() < end_time:
        pass

def cpu_stress_test(duration_sec=10):
    import multiprocessing

    print("[*] Starting CPU stress test for 10 seconds per core...")
    end_time = time.time() + duration_sec
    processes = []
    for _ in range(multiprocessing.cpu_count()):
        p = multiprocessing.Process(target=cpu_stress_worker, args=(end_time,))
        p.start()
        processes.append(p)
    for p in processes:
        p.join()
    print("[*] CPU stress test completed.")

def hardware_test_main():
    output = []
    output.append(f"Hardware Test Report - {datetime.datetime.now()}\n")

    output.append("=== CPU Info ===")
    cpu_cmd = "Get-CimInstance Win32_Processor | Select-Object Name,NumberOfCores,NumberOfLogicalProcessors | Format-List"
    output.append(run_powershell(cpu_cmd))

    cpu_stress_test()

    output.append("\n=== RAM Info ===")
    ram_cmd = "Get-CimInstance Win32_PhysicalMemory | Select-Object BankLabel,Capacity,Speed | Format-List"
    output.append(run_powershell(ram_cmd))

    output.append("\n=== Disk Info ===")
    disk_cmd = "Get-CimInstance Win32_DiskDrive | Select-Object Model,Size,SerialNumber | Format-List"
    output.append(run_powershell(disk_cmd))

    output.append("\n=== Battery Status ===")
    battery_cmd = "Get-CimInstance Win32_Battery | Select-Object BatteryStatus,EstimatedChargeRemaining | Format-List"
    output.append(run_powershell(battery_cmd))

    output.append("\n=== USB Devices ===")
    usb_cmd = "Get-CimInstance Win32_USBHub | Select-Object DeviceID,Status | Format-List"
    output.append(run_powershell(usb_cmd))

    output.append("\n=== Temperature Sensors ===")
    output.append("For advanced temperature monitoring, please run external tools like HWiNFO or Open Hardware Monitor.\n")

    save_results("\n\n".join(output))

    # Keyboard test in thread (already non-blocking)
    start_keylogger(duration=15)
    save_keylog()

    display_test()

    print("\n[*] All tests completed! Reports saved on your Desktop.")
    input("Press Enter to exit...")

# -------- EXE Builder Function --------

def build_exe():
    script_name = sys.argv[0]  # current script
    desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
    dist_path = desktop_path

    # Check if pyinstaller installed
    try:
        import PyInstaller
    except ImportError:
        print("[!] PyInstaller not installed. Installing now...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])

    # Run pyinstaller command
    command = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--onefile",
        "--noconsole",
        f"--distpath={dist_path}",
        script_name
    ]

    print(f"[*] Building EXE for {script_name} ...")
    try:
        subprocess.run(command, check=True)
        exe_name = os.path.splitext(os.path.basename(script_name))[0] + ".exe"
        exe_path = os.path.join(dist_path, exe_name)
        if os.path.exists(exe_path):
            print(f"[+] Build successful! EXE created at: {exe_path}")
        else:
            print("[!] Build finished but EXE not found.")
    except subprocess.CalledProcessError as e:
        print(f"[!] Error during build: {e}")

# -------- Main Entry --------

if __name__ == "__main__":
    print("Choose an option:\n1. Run Hardware Test\n2. Build EXE on Desktop\n")
    choice = input("Enter 1 or 2: ").strip()
    if choice == "1":
        hardware_test_main()
    elif choice == "2":
        build_exe()
    else:
        print("Invalid choice. Exiting.")
