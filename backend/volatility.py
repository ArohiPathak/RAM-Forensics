import subprocess
import os


MEMORY_FILE = "sample_dump/Win11Dump.mem"
OUTPUT_DIR = "output"

os.makedirs(OUTPUT_DIR, exist_ok=True)


def run_plugin(plugin, output_file):
    command = [
        "/home/kali/Desktop/RAM-Forensics/.venv/bin/vol",
        "-f",
        MEMORY_FILE,
        plugin
    ]

    result = subprocess.run(command, capture_output=True, text=True)

    with open(os.path.join(OUTPUT_DIR, output_file), "w") as f:
        f.write(result.stdout)

    print(f"{output_file} created!")

print("Running System Info...")
run_plugin(
    "windows.info.Info",
    "system_info.txt"
)

print("Running Process List...")
run_plugin(
    "windows.pslist.PsList",
    "processes.txt"
)

print("Running Network Scan...")
run_plugin(
    "windows.netscan.NetScan",
    "netscan.txt"
)

print("Running DLL List...")
run_plugin(
    "windows.dlllist.DllList",
    "dlls.txt"
)

print("Running Command Line...")
run_plugin(
    "windows.cmdline.CmdLine",
    "cmdline.txt"
)

print("\nAnalysis Completed!")
