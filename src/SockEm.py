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
from datetime import datetime, timezone
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

## You can customize your CTI sources here. Has to be a freetext or csv format for now though.
import csv, time, os, copy, glob, json, socket
DAEMONIZE = True if os.getenv("DAEMONIZE") == "1" else False

RULESET = glob.glob("ruleset/*.json")
extracted_rid = []

ruleset = []

detected = []
def get_outbound_ip():
    ip_addr = "127.0.0.1"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip_addr = s.getsockname()[0]
        s.close()    
    except socket.error:
        pass

    return ip_addr
    


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

            return rule["rule_id"],rule["description"].format(process),rule["severity"],process

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
                
            return rule["rule_id"],rule["description"].format(process),rule["severity"],process
    
def match_state(rule,process):
    rule_id = rule["rule_id"]
    
    memory_threshold  = rule["match_state"]["memory_kb"]
    
    try:
        mem_threshold = int(memory_threshold.split(">")[-1])

    except ValueError as ve:
        print("VALUE ERROR, memory_kb is invalid..")
    
    kb_process = process["Memory_Usage"]

    verdict = False

    if kb_process > mem_threshold:
        if not check_detected(process["ID"]):
            print("[{}]".format(rule["severity"]),end=' ')
            print(rule["description"].format(process),end=' ')
            print(rule["rule_id"])
            
        return rule["rule_id"],rule["description"].format(process),rule["severity"],process
            
def match_blacklist_port(rule,process):
    rule_id = rule["rule_id"]

    if "src_port" not in process.keys():
        
        return

    port_list = rule["match_blacklist_port"]
    src_port = process["src_port"] or None
    if src_port:
        if int(src_port) in port_list:
            if not check_detected(process["ID"]):
                print("[{}]".format(rule["severity"]),end=' ')
                print(rule["description"].format(process),end=' ')
                print(rule["rule_id"])
            return rule["rule_id"],rule["description"].format(process),rule["severity"],process
def load_ruleset():
    for rules in RULESET:
        with open(rules,"r") as reader:
            rule_data = json.load(reader)

            for rule in rule_data:
                if rule["rule_id"] not in extracted_rid:
                    extracted_rid.append(rule["rule_id"])
                    ruleset.append(rule)
    
        
def check_process_with_ruleset(proc_data):
    # load rulesets
    keys = ("rule_id","description","severity","process_data")
    
    matches = []

    for rules in ruleset:
        
        if "match_state" in rules.keys():
            result_match = match_state(rules,proc_data)
            if result_match:
                matches.append(dict(zip(keys,result_match)))

            
        if "match_blacklist_process" in rules.keys():
            result_match = match_blacklist_process(rules,proc_data)
            if result_match:
                matches.append(dict(zip(keys,result_match)))
            
            
            
        if "match_blacklist_port" in rules.keys():
            result_match = match_blacklist_port(rules,proc_data)
            
            if result_match:
                matches.append(dict(zip(keys,result_match)))
            

        if "match_process_pair" in rules.keys():
            result_match = match_process_pair(rules,proc_data)  
            if result_match:
                matches.append(dict(zip(keys,result_match)))
    return matches

def parse_ps_data():
    if sys.platform == "win32":
        # Powershell power
        cmd = [
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-Command","ps | Select-Object Handles, NPM, PM, WS, @{Name='CPU'; Expression={if ($_.CPU -ne $null) {$_.CPU} else {0.0}}},Id,SI,ProcessName | Format-Table -AutoSize"

        ]

        keys = ["Handles", "NPM(K)", "PM(K)", "Memory_Usage", "CPU(s)","ID", "USER","PROCESSNAME"]

    else:  # Linux/macOS
        # good ol' linux
        cmd = ["ps","-aux"]
        keys = ["USER","ID","%CPU","%MEM","VSZ","Memory_Usage","TTY","STAT","START","TIME", "PROCESSNAME"]

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
            result["Memory_Usage"] = int(float(result["Memory_Usage"] ) / 1024)

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
            # src_ip_raw = conn_info["src"].split(":")[0]
            # dst_ip_raw = conn_info["dst"].split(":")[0]
            
            # src_ip, dst_ip = src_ip_raw if "[" != src_ip_raw else "127.0.0.1", dst_ip_raw if "[" != dst_ip_raw else "127.0.0.1"
            
            # if src_ip == dst_ip:
            #     continue
            conn_info["src"] = conn_info["src"].replace("[::]","0.0.0.0")

            conn_info["src"] = conn_info["src"].replace("[::1]","127.0.0.1")
            
            conn_info["src"] = conn_info["src"].replace("::1","127.0.0.1")
            
            conn_info["dst"] = conn_info["dst"].replace("[::]","0.0.0.0")

            conn_info["dst"] = conn_info["dst"].replace("[::1]","127.0.0.1")
            
            conn_info["dst"] = conn_info["dst"].replace("::1","127.0.0.1")
            
            results.append(conn_info)

    return results
def run_scan(timestamp,hostname,proc_cache):
    
    process_info = {
        "connections":[],
        "highlighted":[],
        "processes":[],
        "matched":[]
    }
    # if not threat_ips:
        
    #     print("[!] No threat IPs found, skipping scan.", file=sys.stderr)
        
    #     sys.exit(1)
 #   print("[*] Scanning active network connections...")
    connections = parse_netstat()
    
    process_running = parse_ps_data()

    process_info["processes"] = process_running

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
                
                matches = check_process_with_ruleset(process_running[final_pid])

                process_info["matched"] += matches

            process_info["connections"].append(process_running[final_pid])
                
            # if final_pid in prev_cache or final_pid not in process_running.keys():
            #     continue

            
    missing = list(set(prev_cache).difference(set(proc_cache)))

    for items in missing:
        print(f"[...] INFO: Process {items} has exited..")
    return proc_cache,process_info
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

    timestamp = datetime.now(timezone.utc).isoformat()
    
    hostname = get_hostname()

    proc_cache = []

    heartbeat_data = {}
    
    heartbeat_data["hostname"] = hostname
    
    print(f"\n[+] Forensic Network Scan - {timestamp} (Hostname: {hostname})")
    
    while True:
        timestamp = datetime.now(timezone.utc).isoformat()
        
        heartbeat_data["outbound_ip"] = get_outbound_ip()
        
        heartbeat_data["timestamp"] = timestamp

        proc_cache,process_heartbeat = run_scan(timestamp,hostname,proc_cache)

        heartbeat_data["beat"] = process_heartbeat
        

        with open("ps_heartbeat.json","w") as ps_heartbeat:
            json.dump(heartbeat_data,ps_heartbeat)

        if not DAEMONIZE:
            
            break
        
        time.sleep(3)



