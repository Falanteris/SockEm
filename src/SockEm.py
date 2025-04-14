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
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

## You can customize your CTI sources here. Has to be a freetext or csv format for now though.
import csv, time, os, copy, glob, json
DAEMONIZE = True if os.getenv("DAEMONIZE") == "1" else False

RULESET = glob.glob("ruleset/*.json")
extracted_rid = []

ruleset = []

detected = []

def check_detected(pid):
    if pid in detected:
        return True
    
    detected.append(pid)

    return False
def match_process_pair(rule,process):    
    rule_id = rule["rule_id"]

    if "dst_port" not in process.keys():
        return
    
    proc_parts = process["PROCESSNAME"].split("\\") if sys.platform == "windows" else process["PROCESSNAME"].split("/")
    real_name = proc_parts[-1]
    for whitelist in rule["match_process_pair"]:

        valids = any([real_name.startswith(valid) for valid in whitelist["valid_process"]])
        
        port_valid = whitelist["port"] == int(process["dst_port"] if process["dst_port"] not in ('*','') else 0)

        if not valids and port_valid:
            if not check_detected(process["ID"]):
                print("[{}]".format(rule["severity"]),end=' ')
                print(rule["description"].format(process),end=' ')
                print(rule["rule_id"])

def match_blacklist_process(rule,process):    
    
    rule_id = rule["rule_id"]
    
    for blacklist in rule["match_blacklist_process"]:
        
        proc_parts = process["PROCESSNAME"].split("\\") if sys.platform == "windows" else process["PROCESSNAME"].split("/")

        real_name = proc_parts[-1]
        if real_name.startswith(blacklist):
            if not check_detected(process["ID"]):
                print("[{}]".format(rule["severity"]),end=' ')
                print(rule["description"].format(process),end=' ')
                print(rule["rule_id"])
    
def match_state(rule,process):
    rule_id = rule["rule_id"]
    
    memory_threshold  = rule["match_state"]["memory_kb"]
    
    try:
        mem_threshold = int(memory_threshold.split(">")[-1])

    except ValueError as ve:
        print("VALUE ERROR, memory_kb is invalid..")
    
    kb_process = int(float(process["%MEM"]) / 1000)

    verdict = False

    if kb_process > mem_threshold:
        if not check_detected(process["ID"]):
            print("[{}]".format(rule["severity"]),end=' ')
            print(rule["description"].format(process),end=' ')
            print(rule["rule_id"])
            
def match_blacklist_port(rule,process):
    rule_id = rule["rule_id"]

    if "src_port" not in process.keys():
        
        return

    port_list = rule["match_blacklist_port"]
    
    if process["src_port"] in port_list:
        if not check_detected(process["ID"]):
            print("[{}]".format(rule["severity"]),end=' ')
            print(rule["description"].format(process),end=' ')
            print(rule["rule_id"])

def load_ruleset():
    for rules in RULESET:
        with open(rules,"r") as reader:
            rule_data = json.load(reader)

            for rule in rule_data:
                if rule["rule_id"] not in extracted_rid:
                    extracted_rid.append(rule["rule_id"])
                    ruleset.append(rule)
    
    pass
        
def check_process_with_ruleset(proc_data):
    # load rulesets

    for rules in ruleset:
    
        if "match_state" in rules.keys():
            match_state(rules,proc_data)
            #TODO: match_state
        if "match_blacklist_process" in rules.keys():
            match_blacklist_process(rules,proc_data)
            
        if "match_blacklist_port" in rules.keys():
            match_blacklist_port(rules,proc_data)

        if "match_process_pair" in rules.keys():
            
            match_process_pair(rules,proc_data)
            
    

    pass

CTI_SOURCES = [  
            "https://threatview.io/Downloads/High-Confidence-CobaltStrike-C2%20-Feeds.txt",
            "https://cdn.ellio.tech/community-feed",
            "https://cinsscore.com/list/ci-badguys.txt" 
]

IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
SCRIPT_SUFFIX = ("python", "php", "perl", "curl", "wget", "./","telnet","ssh","rsync")

def parse_ps_data():
    if sys.platform == "win32":
        # Powershell power
        cmd = [
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-Command","ps | Select-Object Handles, NPM, PM, WS, @{Name='CPU'; Expression={if ($_.CPU -ne $null) {$_.CPU} else {0.0}}},Id,SI,ProcessName | Format-Table -AutoSize"
        ]

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

def query_threat_intel(source):
    """Fetches high-confidence Cobalt Strike C2 IPs and returns them as a set."""
    source_data = urlparse(source)
    proto = source_data.scheme
    fqdn = source_data.netloc
    path = source_data.path
    try:
        if proto == "https":
            client = http.client.HTTPSConnection
        else:
            client = http.client.HTTPConnection
        conn = client(fqdn, timeout=5)
        conn.request("GET", path)
        r1 = conn.getresponse()
        if r1.status != 200:
            print(f"[ERROR] Failed to fetch threat intel (HTTP {r1.status})", file=sys.stderr)
            return set()
        return r1.read().decode().strip().split("\n")
    except Exception as e:
        print(f"[ERROR] Failed to fetch threat intel: {e}", file=sys.stderr)
        return set()
def load_threat_data(file_path):
    """Load threat intel from a local CSV file."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return f.read().splitlines()
    except Exception as e:
        print(f"[ERROR] Failed to load {file_path}: {e}")
        return []
def parse_csv(lines):
    """Parse CSV lines and extract IPs."""
    threats = set()
    reader = csv.reader(lines)
    for row in reader:
        if row:  # Assume IP is in the first column
            for cell in row:  # Scan all columns for an IP
                match = IP_REGEX.search(cell)
                if match:
                    ip = match.group()
                    if ip not in threats:    
                        threats.add(match.group())
                        break  # Stop at the first valid IP in the row
    return threats

def aggregate(sources):
    
    threat_ips = set()

    with ThreadPoolExecutor(max_workers=5) as executor:
        results = executor.map(lambda src: query_threat_intel(src) if src.startswith("http") else load_threat_data(src), sources)
    
    for result in results:
        
        threat_ips.update(parse_csv(result))
    return threat_ips

def parse_netstat():
    """Parses netstat output for active network connections."""
    if sys.platform == "win32":
        cmd = ["netstat", "-ano"]
        keys = ["proto", "src", "dst", "state", "pid"]
    elif sys.platform == "darwin":
        cmd = ["lsof", "-i", "-nP"]
        keys = ["process_name", "pid","user","file_descriptor","socket_type","kernel_device", "sizeof", "proto","conn_details"]

    else:  # Linux
        cmd = ["netstat", "-tunpa"]
        keys = ["proto", "recv-q", "send-q", "src", "dst", "state", "pid"]

    try:
        output = subprocess.check_output(cmd, text=True).strip()
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to execute netstat: {e}", file=sys.stderr)
        return []

    lines = output.split("\n")[2:]  # Skip headers
    results = []
    if sys.platform == "darwin":
        for line in lines:
            columns = re.split(r"\s+", line.strip())  # Handle multiple spaces
            if len(columns) < len(keys):
                continue  # Skip malformed lines

            conn_info = dict(zip(keys, columns))
            conn_data = conn_info["conn_details"].split(" ")
            conn_info["state"] = conn_data[1] if len(conn_data) > 1 else "UNKNOWN"
            ip_data = tuple([parts.split(":")[0] for parts in conn_data[0].split("->")])
            src_ip, dst_ip = ip_data if len(ip_data) == 2 else tuple(list(ip_data)*2)
            # if src_ip == dst_ip:
            #     continue

            conn_info["src"] = src_ip

            conn_info["dst"] = dst_ip

            results.append(conn_info)


    else:
        for line in lines:
            columns = re.split(r"\s+", line.strip())  # Handle multiple spaces
            if len(columns) < len(keys):
                continue  # Skip malformed lines

            conn_info = dict(zip(keys, columns))

            # Ensure source and destination are not the same (same host issue)
            src_ip, dst_ip = conn_info["src"].split(":")[0], conn_info["dst"].split(":")[0]
            # if src_ip == dst_ip:
            #     continue

            results.append(conn_info)

    return results
def run_scan(timestamp,hostname,proc_cache):
    
    process_running = parse_ps_data()
    
    # if not threat_ips:
        
    #     print("[!] No threat IPs found, skipping scan.", file=sys.stderr)
        
    #     sys.exit(1)
 #   print("[*] Scanning active network connections...")
    connections = parse_netstat()

    threat_count = 0
    
    prev_cache = copy.copy(proc_cache)
    proc_cache = []
    for conn in connections:
        src = conn["src"].split(":")
        
        dst = conn["dst"].split(":")
    
        src_ip = src[0]
    
        dst_ip = dst[0]

        if len(src) > 1 and src[1] != "0":
            active_listening = src[1]
        
        if len(dst) > 1 and dst[1] != "0":
            active_listening = dst[1]

        if conn.get("state", "").upper().startswith("LISTEN") or conn.get("state", "").upper() == "ESTABLISHED":
            
            final_pid = conn['pid']
            
            if sys.platform == "linux":
                final_pid = conn["pid"].split('/')[0] if "/" in conn["pid"] else "UNREADABLE"
            if final_pid != "UNREADABLE":
                
                proc_cache.append(final_pid)            
                
                process_running[final_pid]["dst_port"] = dst[1]

                process_running[final_pid]["src_port"] = src[1]

                process_running[final_pid]["dst_ip"] = dst[0]

                process_running[final_pid]["src_ip"] = src[0]
                check_process_with_ruleset(process_running[final_pid])
            
            if final_pid in prev_cache or final_pid not in process_running.keys():
                continue

            
            if sys.platform == "darwin":
                proc_name = conn["process_name"]
                if proc_name.startswith(SCRIPT_SUFFIX):
                    print(f"[+++] WARNING: Active connections on {active_listening} from {src_ip} to {dst_ip} for Process { process_running[final_pid] if final_pid != 'UNREADABLE' else final_pid } ")
                    
            # else:
                #     print(f"[...] INFO: Active connections on {active_listening} for Process { process_running[final_pid] if final_pid != 'UNREADABLE' else final_pid } ") 
            
            else:
                proc_name = process_running[final_pid]["PROCESSNAME"]
                if proc_name.startswith(SCRIPT_SUFFIX):
                    print(f"[+++] WARNING: Active connections on {active_listening} from {src_ip} to {dst_ip} for Process { process_running[final_pid] if final_pid != 'UNREADABLE' else final_pid } ")         
                    
                # else:
                #     print(f"[...] INFO: Active connections on {active_listening} for Process { process_running[final_pid] if final_pid != 'UNREADABLE' else final_pid } ") 

        # if src_ip in threat_ips:
        #     print(f"[!] ALERT: Source {src_ip} is a known threat. [Proto: {conn['proto']}, Status: {conn.get('status', 'N/A')}]")
        #     threat_count += 1
        # if dst_ip in threat_ips:
        #     print(f"[!] ALERT: Destination {dst_ip} is a known threat. [Proto: {conn['proto']}, Status: {conn.get('status', 'N/A')}]")
        #     threat_count += 1
        
#    print(f"\n[*] Scan complete: Found {threat_count} threats out of {len(connections)} active connections and {len(process_running.keys())} processes.\n")        
    missing = list(set(prev_cache).difference(set(proc_cache)))

    for items in missing:
        print(f"[...] INFO: Process {items} has exited..")
    return proc_cache
if __name__ == "__main__":
    
    load_ruleset()

    print("""
       _____            _    ______ __  __ 
  / ____|          | |  |  ____|  \/  |
 | (___   ___   ___| | _| |__  | \  / |
  \___ \ / _ \ / __| |/ /  __| | |\/| |
  ____) | (_) | (__|   <| |____| |  | |
 |_____/ \___/ \___|_|\_\______|_|  |_|
                                       
                                       
    """)

    print("Do you know who are you talking to.. ?")
    print("")
    print("")


    # print("[*] Fetching threat intelligence data...")
    
    # threat_ips = aggregate(CTI_SOURCES)
    
    # print(f"[*] Loaded {len(threat_ips)} threat indicators.")
    
    timestamp = datetime.utcnow().isoformat()
    
    hostname = get_hostname()

    proc_cache = []
    
    print(f"\n[+] Forensic Network Scan - {timestamp} (Hostname: {hostname})")
    
    while True:
        
        proc_cache = run_scan(timestamp,hostname,proc_cache)

        if not DAEMONIZE:
            break

        time.sleep(5)




