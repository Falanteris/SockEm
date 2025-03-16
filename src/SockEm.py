# SockEm - Forensic Network Scanner
# Copyright (C) 2025 Falanteris
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
import subprocess
import sys
import re
import http.client
import socket
from datetime import datetime
# fkk it we ball
def parse_ps_data():
    if sys.platform == "win32":
        # Powershell power
        cmd = ["powershell","-Command","ps | Select-Object Handles, NPM, PM, WS, @{Name='CPU'; Expression={if ($_.CPU -ne $null) {$_.CPU} else {0.0}}},Id,SI,ProcessName | Format-Table -AutoSize"]
        keys = ["Handles", "NPM(K)", "PM(K)", "%MEM", "CPU(s)",  "ID", "USER","PROCESSNAME"]

    else:  # Linux/macOS
        # good ol' linux
        cmd = ["ps","-aux"]
        keys = ["USER","ID","%CPU","%MEM","VSZ","RSS","TTY","STAT","START","TIME", "PROCESSNAME"]

    try:
        data = subprocess.check_output(cmd).decode().strip().split("\n")[2:]
        
    except subprocess.CalledProcessError as se:
        print(f"[ERROR] Failed to execute netstat: {e}", file=sys.stderr)
        return []
    # now comes the parsing part
    results = [dict(zip(keys,list(filter(None,items.split(" "))))) for items in data]
    # converting to K/V basedon processID as the key    
    process_kv = dict()
    for result in results:
        if sys.platform == "win32":
            result["USER"] = "SYSTEM" if result["USER"] == "0" else result["USER"]
        process_kv[result["ID"]] = result
    return process_kv
    
def get_hostname():
    """Retrieve the system hostname."""
    return socket.gethostname()

def query_threat_intel():
    """Fetches high-confidence Cobalt Strike C2 IPs and returns them as a set."""
    try:
        conn = http.client.HTTPSConnection("threatview.io", timeout=5)
        conn.request("GET", "/Downloads/High-Confidence-CobaltStrike-C2%20-Feeds.txt")
        r1 = conn.getresponse()

        if r1.status != 200:
            print(f"[ERROR] Failed to fetch threat intel (HTTP {r1.status})", file=sys.stderr)
            return set()

        raw_data = r1.read().decode().strip().split("\n")[3:]  # Skip headers
        
        threat_ips = set()
        for line in raw_data:
            values = line.split(",")
            if len(values) >= 1:
                threat_ips.add(values[0].strip())  # First column = IP

        return threat_ips

    except Exception as e:
        print(f"[ERROR] Failed to fetch threat intel: {e}", file=sys.stderr)
        return set()

def parse_netstat():
    """Parses netstat output for active network connections."""
    if sys.platform == "win32":
        cmd = ["netstat", "-ano"]
        keys = ["proto", "src", "dst", "status", "pid"]
    else:  # Linux/macOS
        cmd = ["netstat", "-tunp"]
        keys = ["proto", "recv-q", "send-q", "src", "dst", "state", "pid"]

    try:
        output = subprocess.check_output(cmd, text=True).strip()
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to execute netstat: {e}", file=sys.stderr)
        return []

    lines = output.split("\n")[2:]  # Skip headers
    results = []

    for line in lines:
        columns = re.split(r"\s+", line.strip())  # Handle multiple spaces
        if len(columns) < len(keys):
            continue  # Skip malformed lines

        conn_info = dict(zip(keys, columns))

        # Ensure source and destination are not the same (same host issue)
        src_ip, dst_ip = conn_info["src"].split(":")[0], conn_info["dst"].split(":")[0]
        if src_ip == dst_ip:
            continue

        results.append(conn_info)

    return results

if __name__ == "__main__":
    process_running = parse_ps_data()

    timestamp = datetime.utcnow().isoformat()
    hostname = get_hostname()

    print(f"\n[+] Forensic Network Scan - {timestamp} (Hostname: {hostname})")
    print("[*] Fetching threat intelligence data...")

    threat_ips = query_threat_intel()
    if not threat_ips:
        print("[!] No threat IPs found, skipping scan.", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Loaded {len(threat_ips)} threat indicators.")

    print("[*] Scanning active network connections...")
    connections = parse_netstat()

    threat_count = 0
    for conn in connections:
        src = conn["src"].split(":")
        dst = conn["dst"].split(":")
    
        src_ip = src[0]
    
        dst_ip = dst[0]
    
        if len(src) > 1 and src[1] != "0":
            active_listening = src[1]
        if len(dst) > 1 and dst[1] != "0":
            active_listening = dst[1]

        if conn.get("status", "").upper() == "LISTENING" or conn.get("state", "").upper() == "LISTENING" :
            print(f"[~] WARNING: Active connections on {active_listening} for Process { process_running[conn["pid"]] } ") 
        if src_ip in threat_ips:
            print(f"[!] ALERT: Source {src_ip} is a known threat. [Proto: {conn['proto']}, Status: {conn.get('status', 'N/A')}]")
            threat_count += 1
        if dst_ip in threat_ips:
            print(f"[!] ALERT: Destination {dst_ip} is a known threat. [Proto: {conn['proto']}, Status: {conn.get('status', 'N/A')}]")
            threat_count += 1

    print(f"\n[*] Scan complete: Found {threat_count} threats out of {len(connections)} active connections and {len(process_running.keys())} processes.\n")
