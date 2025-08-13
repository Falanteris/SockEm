import http.client
import sys
from urllib.parse import urlparse
import re
class TIManager:
    def __init__(self, ti: list):
        """Initializes the TIManager with a list of threat intel dictionaries."""
        self.ti = ti # list of ti dictionaries
    def query_threat_intel(self, source):
        """Queries the threat intel source and returns a set of malicious IPs."""
        if not source:
            print("[ERROR] No threat intel source provided", file=sys.stderr)
            return set()
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
    def parse_threat_intel(self):
        """Parses the threat intel data and returns a set of malicious IPs."""
        self.parsed_ti = []
        for ti in self.ti:
            results = []
            results.extend(self.query_threat_intel(ti.get("source")))
            results = set(results)  # Remove duplicates
            data_type = ti.get("type")
            if data_type == "freetext":
                self.parsed_ti.extend([{"ip_addr":result,"source":ti.get("source")} for result in results])
            elif data_type == "csv":
                ip_regex = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
                ips = []
                for line in results:
                    fields = line.split(",")
                    for field in fields:
                        match = ip_regex.search(field)
                        if match:
                            ips.append({"ip_addr":match.group(),"source": ti.get("source")})
                    
                self.parsed_ti.extend(ips)
        
        return self.parsed_ti
    def match_ip(self, process):
        """Matches the process IP against the parsed threat intel."""
        if not hasattr(self, 'parsed_ti'):
            self.parse_threat_intel()
        src_ip = process.get("src_ip")
        dst_ip = process.get("dst_ip")
        if not src_ip or not dst_ip:
            return None
        for ti in self.parsed_ti:
            if isinstance(ti, dict) and (ti.get("ip_addr") == src_ip or ti.get("ip_addr") == dst_ip):
                return {"src_ip": src_ip, "dst_ip": dst_ip, "rule_description": f"IP matched threat intel list from {ti.get('source')}", "severity": "CRITICAL", "rule_id": "CTI_MATCH"}
        return None
