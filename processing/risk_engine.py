import pandas as pd
from parser import load_all_outputs, parse_volatility_txt

# A small reference list of well-known, trusted Windows DLLs.
# Any DLL NOT in this list, or with a missing path, is flagged as "Unknown".
KNOWN_DLLS = {
    "ntdll.dll", "kernel32.dll", "kernelbase.dll", "user32.dll", "gdi32.dll",
    "gdi32full.dll", "win32u.dll", "advapi32.dll", "msvcrt.dll", "sechost.dll",
    "rpcrt4.dll", "combase.dll", "ucrtbase.dll", "shell32.dll", "shlwapi.dll",
    "ole32.dll", "oleaut32.dll", "wintrust.dll", "crypt32.dll", "bcrypt.dll",
    "psapi.dll", "imm32.dll", "msctf.dll", "setupapi.dll", "cfgmgr32.dll",
    "csrsrv.dll", "basesrv.dll", "winsrv.dll", "winsrvext.dll", "msvcp_win.dll",
    "dwmapi.dll", "uxtheme.dll", "clbcatq.dll",
}

# Private/reserved IP ranges — anything outside these counts as "external"
PRIVATE_PREFIXES = ("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
                     "172.2", "172.30.", "172.31.", "127.", "0.0.0.0", "::", "169.254.")


def detect_hidden_processes(base_path="processing/sample_output"):
    """
    Compares psscan (raw scan, sees everything) vs pslist (normal listing).
    PIDs present in psscan but missing from pslist are considered hidden.
    """
    pslist = parse_volatility_txt(f"{base_path}/pslist.txt")
    psscan = parse_volatility_txt(f"{base_path}/psscan.txt")

    if pslist.empty or psscan.empty:
        return []

    pslist_pids = set(pslist["PID"].astype(str))
    psscan_pids = set(psscan["PID"].astype(str))

    hidden_pids = psscan_pids - pslist_pids
    hidden_processes = psscan[psscan["PID"].astype(str).isin(hidden_pids)]

    return hidden_processes.to_dict(orient="records")


def detect_unknown_dlls(base_path="processing/sample_output"):
    """
    Flags DLLs that have no path, or whose name isn't in the known-good list.
    """
    dlllist = parse_volatility_txt(f"{base_path}/dlllist.txt")
    if dlllist.empty:
        return []

    def is_unknown(row):
        name = str(row.get("Name", "")).strip().lower()
        path = str(row.get("Path", "")).strip()
        if path == "-" or path == "":
            return True
        if name not in KNOWN_DLLS and name.endswith(".dll"):
            return True
        return False

    unknown = dlllist[dlllist.apply(is_unknown, axis=1)]
    return unknown.to_dict(orient="records")


def is_private_ip(ip):
    ip = str(ip).strip()
    return any(ip.startswith(prefix) for prefix in PRIVATE_PREFIXES)


def detect_external_connections(base_path="processing/sample_output"):
    """
    Flags ESTABLISHED connections where the ForeignAddr is a public IP.
    """
    netscan = parse_volatility_txt(f"{base_path}/netscan.txt")
    if netscan.empty:
        return []

    mask = (
        (netscan["State"].str.strip() == "ESTABLISHED") &
        (~netscan["ForeignAddr"].apply(is_private_ip)) &
        (netscan["ForeignAddr"].str.strip() != "*")
    )
    external = netscan[mask]
    return external.to_dict(orient="records")


def detect_powershell(base_path="processing/sample_output"):
    """
    Flags any process whose command line involves powershell.exe.
    """
    cmdline = parse_volatility_txt(f"{base_path}/cmdline.txt")
    if cmdline.empty:
        return []

    mask = cmdline["Process"].str.lower().str.contains("powershell", na=False) | \
           cmdline["Args"].str.lower().str.contains("powershell", na=False)
    ps = cmdline[mask]
    return ps.to_dict(orient="records")


def calculate_risk_score(base_path="processing/sample_output"):
    """
    Runs all detections and calculates a total risk score.
    Scoring rules (from project spec):
        Hidden Process      +40
        Unknown DLL         +20
        External Connection +20
        PowerShell          +20
    """
    hidden = detect_hidden_processes(base_path)
    unknown_dlls = detect_unknown_dlls(base_path)
    external_conns = detect_external_connections(base_path)
    powershell = detect_powershell(base_path)

    score = 0
    findings = []

    if hidden:
        score += 40
        findings.append(f"Hidden Process detected ({len(hidden)} found) [+40]")
    if unknown_dlls:
        score += 20
        findings.append(f"Unknown DLL detected ({len(unknown_dlls)} found) [+20]")
    if external_conns:
        score += 20
        findings.append(f"External Connection detected ({len(external_conns)} found) [+20]")
    if powershell:
        score += 20
        findings.append(f"PowerShell activity detected ({len(powershell)} found) [+20]")

    if score >= 80:
        risk_level = "Critical"
    elif score >= 60:
        risk_level = "High"
    elif score >= 30:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return {
        "score": score,
        "risk_level": risk_level,
        "findings": findings,
        "details": {
            "hidden_processes": hidden,
            "unknown_dlls": unknown_dlls,
            "external_connections": external_conns,
            "powershell_activity": powershell,
        }
    }


if __name__ == "__main__":
    result = calculate_risk_score()
    print(f"\n=== RISK ASSESSMENT ===")
    print(f"Score: {result['score']}")
    print(f"Risk Level: {result['risk_level']}")
    print(f"\nFindings:")
    for f in result["findings"]:
        print(f"  - {f}")
    print(f"\nHidden processes: {len(result['details']['hidden_processes'])}")
    print(f"Unknown DLLs: {len(result['details']['unknown_dlls'])}")
    print(f"External connections: {len(result['details']['external_connections'])}")
    print(f"PowerShell activity: {len(result['details']['powershell_activity'])}")
