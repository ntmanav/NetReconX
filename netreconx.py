# NetReconX - Network Reconnaissance Tool
# Author: manav Narwade
# i'm a 16 year old boy 
import argparse
import socket
import threading
import json
from datetime import datetime
from queue import Queue
import sys

# === Global Variables ===
open_ports = []
queue = Queue()
print_lock = threading.Lock()

# === Port Scanner ===
def scan_port(target, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((target, port))
            if result == 0:
                with print_lock:
                    print(f"[+] Port {port} is open")
                open_ports.append(port)
    except Exception:
        pass

# === Thread Worker ===
def threader(target):
    while True:
        worker = queue.get()
        scan_port(target, worker)
        queue.task_done()

# === Save Report ===
def save_report(target, open_ports, output_file):
    report = {
        "target": target,
        "timestamp": str(datetime.now()),
        "open_ports": open_ports
    }
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=4)
    print(f"\n[+] Report saved to {output_file}")

# === Main Function ===
def main():
    parser = argparse.ArgumentParser(description="NetReconX - Basic Port Scanner")
    parser.add_argument("--target", help="Target IP address", required=True)
    parser.add_argument("--ports", help="Port range, e.g. 1-1024", default="1-100")
    parser.add_argument("--output", help="Output report file (JSON)", default="report.json")

    try:
        if len(sys.argv) == 1:
            raise argparse.ArgumentError(None, "No arguments provided")

        args = parser.parse_args()

        target = args.target

        try:
            port_range = args.ports.split("-")
            if len(port_range) != 2:
                raise ValueError("Invalid port range format. Use start-end (e.g. 1-100).")
            start_port, end_port = int(port_range[0]), int(port_range[1])
            if not (0 < start_port <= end_port <= 65535):
                raise ValueError("Ports must be between 1 and 65535.")
        except ValueError as ve:
            print(f"[!] Error: {ve}")
            return

        print(f"[+] Starting scan on {target} from port {start_port} to {end_port}\n")

        for _ in range(100):
            t = threading.Thread(target=threader, args=(target,), daemon=True)
            t.start()

        for port in range(start_port, end_port + 1):
            queue.put(port)

        queue.join()
        save_report(target, open_ports, args.output)

    except argparse.ArgumentError:
        parser.print_help()
        return

if __name__ == "__main__":
    main()
