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
import platform
import sys
import re
import http.client
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
import threading
import time
import os
import copy
import glob
import json
import base64
import ssl
from urllib.parse import quote_plus
import argparse
import socket

# class Payload(BaseModel):
#     src_ip: str
#     dst_ip: str
#     src_port: int
#     dst_port: int
#     PROCESSNAME: str
#     ID: str
#     Memory_Usage: int
#     hostname: str
#     ip: str
#     os: str
#     type: str

argp = argparse.ArgumentParser(
    description="use interactive or not?"
)

argp.add_argument("--interactive", action="store_true")

cli_args = argp.parse_args()

DAEMONIZE = True if os.getenv("DAEMONIZE") == "1" else False

# BEATEM_ONBD_HOST = os.getenv("BEATEM_ONBD_HOST")
# BEATEM_ONBD_PORT = os.getenv("BEATEM_ONBD_PORT")
# # BeatEm Credentials
# BEATEM_TOKEN = os.getenv("BEATEM_TOKEN")

# OpenSearch credentials

MAX_RETRIES = os.getenv("MAX_RETRIES") or 3

GLOBAL_TIMEOUT = os.getenv("GLOBAL_TIMEOUT") or 5

INTEGRATE_URL = os.getenv("INTEGRATE_URL")

NOTIFY_LEVEL = os.getenv("NOTIFY_LEVEL")

INTERACTIVE = os.getenv("INTERACTIVE")=="1" 
    
extracted_rid = []

ruleset = []

detected = []

config_data = {}

severity_chart = {
    "INFO":1,
    "MEDIUM":2,
    "HIGH":3,
    "CRITICAL":4
}
if sys.platform == "win32":
    # define trusted paths, essential to prevent DLL Search Order Attack
    system_root = os.getenv("SYSTEMROOT")
    
    trusted_path_root = os.path.join(system_root,"System32")
    
    taskkill_path = os.path.join(trusted_path_root,"taskkill.exe")

    wmic_path     = os.path.join(trusted_path_root,"wbem","wmic.exe")
    
    powershell_path = os.path.join(trusted_path_root,"WindowsPowerShell","v1.0","powershell.exe")

    netstat_path = os.path.join(trusted_path_root, "netstat.exe")

def process_enhancement(data: dict):
    pid = data["ID"]
    
    if sys.platform == "win32":
        parent_pid = subprocess.check_output([wmic_path,
        "process","where",
        f"(processid={pid})","get", "parentprocessid"],
        universal_newlines=True).strip().split("\n")[-1]
    else:
        parent_pid = subprocess.check_output(["ps",
        "-o",
        "ppid=",pid],universal_newlines=True).strip().split("\n")[-1].strip()    
    data["PPID"] = parent_pid or None
    
    return data

def send_to_receiver(beat):
    """Send data to receiver for SOAR"""
    ### skips if the alert level doesn't match
    # this should support some older python versions, at least python 3.6
    keys_extract = ("src_ip","dst_ip","dst_port","src_port","PROCESSNAME","ID","Memory_Usage","hostname","ip","os","type")
    to_del = []
    for items in beat.keys():
        if items not in keys_extract:
            to_del.append(items)
    for key in to_del:
        del beat[key]
    if beat["type"] == "exited":
        ## add fluff
        beat["src_ip"] = ""
        beat["dst_ip"] = ""
        beat["src_port"] = -1
        beat["dst_port"] = -1
        beat["state"] = ""

    print(beat)

    fullpath = config_data["url"]

    parsed = urlparse(fullpath)

    receiver_host,receiver_port = parsed.netloc.split(":") if ":" in parsed.netloc else (parsed.netloc, 443)
    
    if parsed.scheme == "https":
        conn = http.client.HTTPSConnection(
            receiver_host, receiver_port, context=ssl._create_unverified_context(),timeout=GLOBAL_TIMEOUT
        )
    else:
        conn = http.client.HTTPConnection(
            receiver_host, receiver_port, timeout=GLOBAL_TIMEOUT
        )

    
    attempt = 0
    
    result = False

    headers = {
            "Content-Type": "application/json"
    }
    # while MAX_RETRIES > attempt:
    try:
        conn.request(
            "POST", parsed.path,
            body=json.dumps(beat), headers=headers
        )
        # Handle response
        response = conn.getresponse()
        
        conn.close()
        
        if response.status >= 200 and response.status < 300:
            result = True
            
    except (TimeoutError, ConnectionRefusedError, socket.gaierror) as e:
        print("Failed when trying to send to Receiver: ",e)
        attempt+=1
    except http.client.CannotSendRequest as e:
        if e == "Request-Sent":
            print("Terminating because our client sent the request already")
    return result

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

def load_receivers():
    global config_data

    config_data = {
        "url":INTEGRATE_URL
    }
    
def parse_ps_data():
    if sys.platform == "win32":
        # Powershell power
        
        cmd = [
        powershell_path,
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
        else:
            result["Memory_Usage"] = int(float(result["Memory_Usage"] ))

        process_kv[result["ID"]] = result
    
    return process_kv
    
def get_hostname():
    """Retrieve the system hostname."""
    return socket.gethostname()

def load_threat_data(file_path):
    """Load threat intel from a local CSV file."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return f.read().splitlines()
    except Exception as e:
        print(f"[ERROR] Failed to load {file_path}: {e}")
        return []

def parse_netstat():
    """Parses netstat output for active network connections."""
    if sys.platform == "win32":
        cmd = [netstat_path, "-ano"]
        keys = ["proto", "src", "dst", "state", "pid"]
    elif sys.platform == "darwin":
        cmd = ["lsof", "-i", "-nP"]
        keys = ["process_name", "pid","user","file_descriptor","socket_type","kernel_device", "sizeof", "proto","conn_details"]

    else:  # Linux
        cmd = ["netstat", "-tunpa"]
        keys = ["proto", "recv-q", "send-q", "src", "dst", "state", "pid"]

    try:
        output = subprocess.check_output(cmd, universal_newlines=True).strip()
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
            # src parsing
            
            results.append(conn_info)

    return results
def run_scan(timestamp,hostname,proc_cache,process_info):
    
    # process_info = {
    #     "connections":[],
    #     "processes":[],
    #     "matched":[]
    # }
    old_process_info = process_info.copy()

    process_info = {
        "connections":[],
        "processes":[],
        "matched":[],
        "exited":[],
    }

    
    process_running = parse_ps_data()
    
    connections = parse_netstat()
    
    process_info["processes"] = process_running

    prev_cache = copy.copy(proc_cache)
    
    proc_cache = []

    laterals = []

    check_v4v6 = lambda socket_vercheck: socket_vercheck[0] if len(socket_vercheck) == 2 else ":".join(socket_vercheck[:-1])
    
    for conn in connections:

        src = conn["src"].split(":")
        
        dst = conn["dst"].split(":")

        src_ip = check_v4v6(src) # detect if the IP isn't hexadecimal, if it is, join
    
        dst_ip = check_v4v6(dst) # detect if the IP isn't hexadecimal, if it is, join
        
        if conn.get("state", "").upper().startswith("LISTEN") or conn.get("state", "").upper() == "ESTABLISHED":
            
            final_pid = conn['pid']
            
            if sys.platform == "linux":
                
                final_pid = conn["pid"].split('/')[0] if "/" in conn["pid"] else "UNREADABLE"

            if final_pid != "UNREADABLE" or final_pid in process_running.keys():
                try:
                    process_running[final_pid]["state"] = conn.get("state","").upper()
                except KeyError:
                    continue  # Skip if the PID is not in process_running
                # if sys.platform == "linux":

                #     process_running[final_pid]["parent_id"] = process_id_enhancement(final_pid)["parent_pid"]

                process_running[final_pid]["first_seen"] = datetime.now(timezone.utc).isoformat()
                
                process_running[final_pid]["last_seen"] = None


                if final_pid in proc_cache or final_pid not in process_running.keys():
                    # prevent duplicates, should be more advanced based on the smallest PID?
                    continue
                proc_cache.append(final_pid)
                
                if final_pid in prev_cache:
                    # prevent duplicates for entries.
                    continue
                process_running[final_pid]["dst_port"] = dst[-1]

                process_running[final_pid]["src_port"] = src[-1]

                process_running[final_pid]["dst_ip"] = dst_ip

                process_running[final_pid]["src_ip"] = src_ip
                
                process_info["connections"].append(process_running[final_pid])

                process_info["processes"][final_pid] = process_running[final_pid]
    
    missing = list(set(prev_cache).difference(set(proc_cache)))

    for items in missing:
        print(f"[INFO] Process {items} has exited..", end=' ')

        if items in old_process_info["processes"].keys():
            
            old_process_info["processes"][items]["last_seen"] = datetime.now(timezone.utc).isoformat()

            process_info["exited"].append(old_process_info["processes"][items])
            
            beat = old_process_info["processes"][items]
            
            process_name = beat.get("PROCESSNAME")
            
            last_seen = beat.get("last_seen")
            
            PID = beat.get("ID")
            
            memory = beat.get("Memory_Usage")

            printout = f"ProcessName: {process_name} at {last_seen} with a PID of {PID}. Memory: {memory} kb"
            print(printout)
        else:
            print("")
    
    
    
    return proc_cache,process_info
def stamp_process(process):
    """Stamp process with information."""
    return {**process, 
    "timestamp": datetime.now(timezone.utc).isoformat(), 
    "hostname": get_hostname(), 
    "ip": get_outbound_ip(),
    "os":  platform.uname().system
    }
def print_process_info(beat):
    # this is usually utilized for standalone daemon runs, or script runs
    if "severity" not in beat.keys():
        
        first_seen = beat.get("first_seen")
        
        state = beat.get("state")
        
        PID = beat.get("ID")
        
        src_ip = beat.get("src_ip")
        
        dst_ip = beat.get("dst_ip")

        memory_usage = beat.get("Memory_Usage")
        
        proc_name = beat.get('PROCESSNAME')

        src_port = beat.get("src_port")

        dst_port = beat.get("dst_port")

        printout = f"[INFO] {first_seen} A socket is {state} on PID {PID}: Source: {src_ip}:{src_port} Dest: {dst_ip}:{dst_port} Memory: {memory_usage} kb ProcessName: {proc_name}"
        
def kill_windows_task(pid):
    try:
        subprocess.check_output(["taskkill", "/F", "/PID", str(pid)])
    except Exception as e:
        print(e)

def kill_unix_task(pid):
    try:
        subprocess.check_output(["kill", "-9", str(pid)])
    except Exception as e:
        print(e)
def fetch_specific_process(pid):
    spec_pid = ["wmic", "process", "where", f"processId={pid}", "get", "name"]
    try:
        get_name = subprocess.check_output(spec_pid, universal_newlines=True).strip().split("\n")[-1]
        print(get_name.split("\n"))
    except Exception as e:
        print(e)
    print("NAME: ",get_name)
    return get_name

def pql_query(query: str, heartbeat_data: list, ps_list: list):
    # Query Format
    # <DIRECTIVE (Kill/Report)> <PARENT_PROC_NAME_PATTERN> <PARENT_PROC_CHILD_PATTERN> <DEST_HOST> <PORT>
    item = query.split(" ")
    try:
        directives = ["command","parent","child","dst_host","dst_port"]
        params = dict(zip(directives,item))
    except Exception as e:
        pass
    if params["command"] not in ("Kill","Report"):
        print("Command has to be 'Kill' or 'Report'")
        return
    
    query_exec = lambda beat_arg: all((
        beat_arg["PROCESSNAME"] == params["child"] if params["child"] !='*' else True,
        any((
            beat_arg["dst_ip"] == params["dst_host"] if params["dst_host"] !='*' else True,
            beat_arg["dst_ip"] not in ("127.0.0.1","[::]","[::1]","0.0.0.0") if params["dst_host"] =='nonlocal' else False
        )),
        any((
            beat_arg["dst_port"] == params["dst_port"] if params["dst_port"] !='*' else True,
            beat_arg["dst_port"] not in ("80","443","22","21","25","53","135","110","143","443","3389") if params["dst_port"] == 'nsp' else False
        ))
    ))
    query_proc_name = lambda heartbeat: [beat_match for beat_match in heartbeat_data if query_exec(beat_match)]
    matching_names = query_proc_name(heartbeat_data)
    match_final = []
    for matches in matching_names:
        matches = process_enhancement(matches)
        
        if params["command"] == "Kill":
            # print(f"!!! KILL", end=' ')
            # prioritize parent PID, kill the process from it's root
            kill_windows_task(matches["PPID"] or matches["PID"]) if sys.platform == "win32" else kill_unix_task(matches["PPID"] or matches["ID"])
        # else:
        #     print(f"!!! REPORT", end=' ')

        # print(f"{matches}")
        
        matches["command"] = params["command"]

        match_final.append(matches)
    return match_final

def tabulate_local(data):
    if data:
        headers = list(data[0].keys())
        # Determine maximum width for each column
        col_widths = {header: len(header) for header in headers}
        for row_dict in data:
            for header in headers:
                col_widths[header] = max(col_widths[header], len(str(row_dict.get(header, ''))))

        # Print header row
        header_line = " | ".join(f"{h:<{col_widths[h]}}" for h in headers)
        print(header_line)
        print("-" * len(header_line))

        # Print data rows
        for row_dict in data:
            row_line = " | ".join(f"{str(row_dict.get(h, '')):<{col_widths[h]}}" for h in headers)
            print(row_line)

if __name__ == "__main__":
    load_receivers()
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
    
    print(f"\n[+] Forensic Network Scan - {timestamp} (Hostname: {hostname})")
    
    process_heartbeat = {
        "connections":[],
        "processes":[],
        "matched":[],
        "exited": []
    }
    # if indexer_host:
    if INTEGRATE_URL:
        print(f"[+] Shuffle URL: {INTEGRATE_URL}")
    else:
        print("[!] Shuffle URL is not configured, skipping SOAR integration..")
    proc_cache,process_heartbeat = run_scan(
                    timestamp,hostname,proc_cache,process_heartbeat
    )
    if cli_args.interactive or INTERACTIVE:
        
        print("Welcome to SockEm's Interactive mode",end='\n\n')
        print("PQL Format [<Kill/Report> <ParentProcessName/*> <ProcessName/nonlocal/*> <port/nsp>]",end='\n\n')
        print("nsp: Non-Standard Port --> Refer to IANA standard port for this")
        print("nonlocal: Anything besides localhost",end='\n\n')
        print("Please enter your PQL: ")
        
        while True:
            try:        
                pql = input("query>> ")
                result = pql_query(
                    pql, 
                    process_heartbeat["connections"],
                    process_heartbeat["processes"]
                )
                tabulate_local(result)
                proc_cache = []
                proc_cache,process_heartbeat = run_scan(
                    timestamp,hostname,proc_cache,process_heartbeat
                )
            except KeyboardInterrupt as ke:
                break
            except Exception as e:
                raise Exception(e)
            
    elif not cli_args.interactive:
        while True:
            try:
                pql_result = [] # result for pql queries
                try:
                    with open("search.pql","r") as pql_data:
                        for pql in pql_data.readlines():
                            if not pql.startswith("#"):
                                # skip comment lines
                                pql_result_temp = pql_query(
                                    pql,
                                    process_heartbeat["connections"],
                                    process_heartbeat["processes"]
                                )
                                pql_result.extend(pql_result_temp)                                
                        if len(pql_result) > 0:
                            print(pql_result)
                except FileNotFoundError as fe:
                    print("No search.pql specified.. Skipping. Define your search.pql on non interactive mode")
                if INTEGRATE_URL:
                    
                    for event in pql_result:
                        stamped = stamp_process(event)
                        stamped["type"] = "pql_result"
                        threading.Thread(target=send_to_receiver,args=[stamped]).start()
                    for event in process_heartbeat["exited"]:
                        stamped = stamp_process(event)
                        stamped["type"] = "exited"
                        threading.Thread(target=send_to_receiver,args=[stamped]).start()
                        
                if not DAEMONIZE:
                    break
                
                time.sleep(3)
                
                proc_cache,process_heartbeat = run_scan(
                    timestamp,hostname,proc_cache,process_heartbeat
                )
            except Exception as e:
                print(f"[ERROR] An error occurred: {e}", file=sys.stderr)
                continue



