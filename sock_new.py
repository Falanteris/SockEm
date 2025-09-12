import socket
import sys

def test_connection(ip, port):
    try:
        # Create TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        
        # Attempt connection
        sock.connect((ip, port))
        print(f"[+] Connected to {ip}:{port}")
        
        sock.close()
    except Exception as e:
        print(f"[-] Could not connect to {ip}:{port} -> {e}")

if __name__ == "__main__":
    # Example Cloudflare IP
    cf_ip = "104.16.132.229"  # belongs to Cloudflare
    target_port = 5055
    
    test_connection(cf_ip, target_port)
