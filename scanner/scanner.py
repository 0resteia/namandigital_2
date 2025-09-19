#!/usr/bin/env python3
"""
A basic localhost scanner.
Usage:
  python scanner.py --host 127.0.0.1 --ports 1-1024 --timeout 0.5 --workers 200
"""

import socket
import argparse
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

COMMON_PORTS = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    443: "https",
    445: "microsoft-ds",
    3306: "mysql",
    3389: "rdp"
}

def scan_port(host, port, timeout=0.5, grab_banner=True):
    result = {"port": port, "open": False, "service": COMMON_PORTS.get(port), "banner": None}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            code = s.connect_ex((host, port))
            if code == 0:
                result["open"] = True
                if grab_banner:
                    try:
                        # small send to provoke banner for some protocols
                        s.sendall(b"\r\n")
                    except Exception:
                        pass
                    try:
                        banner = s.recv(1024)
                        if banner:
                            try:
                                result["banner"] = banner.decode(errors="replace").strip()
                            except Exception:
                                result["banner"] = str(banner)
                    except socket.timeout:
                        pass
                    except Exception:
                        pass
    except Exception as e:
        result["error"] = str(e)
    return result

def parse_ports(port_str):
    ports = set()
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            ports.update(range(int(a), int(b)+1))
        else:
            ports.add(int(part))
    return sorted(ports)

def basic_service_checks(scan_results, host, timeout=1.0):
    checks = []
    # example: anonymous FTP check (non-invasive)
    for r in scan_results:
        if r["open"] and r["port"] == 21:
            try:
                with socket.create_connection((host, 21), timeout=timeout) as s:
                    data = s.recv(512).decode(errors="replace")
                    if "FTP" in data or "ftp" in data:
                        checks.append({"port":21, "check":"ftp_banner", "msg": data.strip()})
                    # attempt to check for anonymous login (very cautious: only attempt if you own host)
                    # We will not try to login automatically; only recommend manual check
                    checks.append({"port":21, "check":"note", "msg":"If FTP is open, verify anonymous login manually if authorized."})
            except Exception as e:
                checks.append({"port":21, "check":"error", "msg":str(e)})
        if r["open"] and r["port"] == 80:
            # HTTP header found in banner?
            if r.get("banner"):
                checks.append({"port":80, "check":"http_banner", "msg": r["banner"]})
            else:
                checks.append({"port":80, "check":"http", "msg":"HTTP port open — fetch / manually to inspect headers."})
    return checks

def run_scan(host, ports, timeout=0.5, workers=200):
    results = []
    start = datetime.utcnow().isoformat() + "Z"
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(scan_port, host, p, timeout): p for p in ports}
        for fut in as_completed(futures):
            res = fut.result()
            results.append(res)
    checks = basic_service_checks(results, host, timeout=max(1.0, timeout))
    end = datetime.utcnow().isoformat() + "Z"
    return {"host": host, "start": start, "end": end, "ports": sorted(results, key=lambda x: x["port"]), "checks": checks}

def main():
    parser = argparse.ArgumentParser(description="Localhost vulnerability/port scanner (non-invasive)")
    parser.add_argument("--host", default="127.0.0.1", help="Target host (default 127.0.0.1)")
    parser.add_argument("--ports", default="1-1024", help="Ports to scan, e.g. 1-1024 or 22,80,443")
    parser.add_argument("--timeout", type=float, default=0.5)
    parser.add_argument("--workers", type=int, default=200)
    parser.add_argument("--output", help="Write JSON output to file")
    args = parser.parse_args()

    ports = parse_ports(args.ports)
    if args.workers > len(ports):
        args.workers = min(args.workers, len(ports))
    res = run_scan(args.host, ports, timeout=args.timeout, workers=args.workers)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(res, f, indent=2)
        print(f"Wrote results to {args.output}")
    else:
        print(json.dumps(res, indent=2))

if __name__ == "__main__":
    main()
