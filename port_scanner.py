#!/usr/bin/env python3
"""
port_scanner.py — Lightweight tech-audit port scanner

Scans a target host for open TCP ports, grabs service banners where
possible, and reports likely running services. Built for authorized
internal audits / asset discovery — only scan hosts you own or have
explicit permission to test.

Two scan engines:
  - socket  (default): TCP connect() scan. No special privileges needed.
  - scapy   (optional, --syn): raw SYN scan. Requires scapy installed
            and root/administrator privileges. Faster and stealthier,
            but needs elevated permissions.

Usage examples:
    python3 port_scanner.py 192.168.1.10
    python3 port_scanner.py 192.168.1.10 -p 1-1024
    python3 port_scanner.py 192.168.1.10 -p 22,80,443,8080
    python3 port_scanner.py 192.168.1.10 --syn -p 1-1024   (needs sudo)
    python3 port_scanner.py 192.168.1.10 -t 200 -o audit.json
"""

import argparse
import concurrent.futures
import json
import socket
import sys
import time
from datetime import datetime, timezone

# --- Well-known service map for quick identification (fallback when banner grab fails) ---
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCBind", 135: "MS-RPC",
    139: "NetBIOS-SSN", 143: "IMAP", 161: "SNMP", 389: "LDAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP-Submission",
    631: "IPP", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
    1521: "Oracle-DB", 2049: "NFS", 2375: "Docker", 3000: "Dev-HTTP",
    3268: "LDAP-GC", 3306: "MySQL", 3389: "RDP", 5000: "HTTP-Alt",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 6443: "Kubernetes-API",
    8000: "HTTP-Alt", 8008: "HTTP-Alt", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
    9000: "HTTP-Alt", 9200: "Elasticsearch", 27017: "MongoDB",
}


def parse_ports(port_spec: str):
    """Parse '80', '1-1024', or '22,80,443,8000-8100' into a sorted list of ints."""
    ports = set()
    for chunk in port_spec.split(","):
        chunk = chunk.strip()
        if "-" in chunk:
            lo, hi = chunk.split("-", 1)
            lo, hi = int(lo), int(hi)
            if lo > hi or lo < 1 or hi > 65535:
                raise ValueError(f"Invalid port range: {chunk}")
            ports.update(range(lo, hi + 1))
        elif chunk:
            p = int(chunk)
            if not (1 <= p <= 65535):
                raise ValueError(f"Invalid port: {p}")
            ports.add(p)
    return sorted(ports)


def grab_banner(sock: socket.socket, port: int) -> str:
    """Try to read a banner; for HTTP-ish ports, send a minimal probe first."""
    try:
        sock.settimeout(1.0)
        if port in (80, 8080, 8000, 8008, 5000, 9000, 3000):
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        data = sock.recv(256)
        if data:
            return data.decode(errors="ignore").strip().split("\n")[0][:120]
    except Exception:
        pass
    return ""


def identify_service(port: int, banner: str) -> str:
    banner_l = banner.lower()
    if "ssh" in banner_l:
        return "SSH"
    if "http" in banner_l or "server:" in banner_l:
        return "HTTP(S)"
    if "ftp" in banner_l:
        return "FTP"
    if "smtp" in banner_l:
        return "SMTP"
    return COMMON_PORTS.get(port, "unknown")


def socket_scan_port(target: str, port: int, timeout: float):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((target, port))
            if result == 0:
                banner = grab_banner(s, port)
                service = identify_service(port, banner)
                return {"port": port, "state": "open", "service": service, "banner": banner}
    except socket.timeout:
        pass
    except OSError:
        pass
    return None


def run_socket_scan(target: str, ports, timeout: float, workers: int):
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(socket_scan_port, target, p, timeout): p for p in ports}
        done = 0
        total = len(futures)
        for fut in concurrent.futures.as_completed(futures):
            done += 1
            if done % 200 == 0 or done == total:
                print(f"\r  scanned {done}/{total} ports...", end="", file=sys.stderr, flush=True)
            res = fut.result()
            if res:
                open_ports.append(res)
    print(file=sys.stderr)
    return sorted(open_ports, key=lambda r: r["port"])


def run_syn_scan(target: str, ports, timeout: float):
    """Raw SYN scan via scapy. Requires scapy + root/administrator privileges."""
    try:
        from scapy.all import sr, IP, TCP  # imported lazily; scapy is optional
    except ImportError:
        print("ERROR: scapy is not installed. Install it with:\n  pip install scapy --break-system-packages",
              file=sys.stderr)
        sys.exit(1)

    open_ports = []
    # Batch to avoid huge single packet lists on big ranges
    batch_size = 500
    for i in range(0, len(ports), batch_size):
        batch = ports[i:i + batch_size]
        pkt = IP(dst=target) / TCP(dport=batch, flags="S")
        try:
            ans, _ = sr(pkt, timeout=timeout, verbose=0)
        except PermissionError:
            print("ERROR: SYN scan requires root/administrator privileges (run with sudo).",
                  file=sys.stderr)
            sys.exit(1)
        for sent, recv in ans:
            if recv.haslayer(TCP) and recv[TCP].flags == 0x12:  # SYN-ACK
                port = sent[TCP].dport
                open_ports.append({
                    "port": port, "state": "open",
                    "service": COMMON_PORTS.get(port, "unknown"), "banner": ""
                })
        print(f"\r  scanned {min(i + batch_size, len(ports))}/{len(ports)} ports...",
              end="", file=sys.stderr, flush=True)
    print(file=sys.stderr)
    return sorted(open_ports, key=lambda r: r["port"])


def main():
    ap = argparse.ArgumentParser(description="Port scanner and service identifier for tech audits.")
    ap.add_argument("target", help="Target hostname or IP address")
    ap.add_argument("-p", "--ports", default="1-1024",
                    help="Ports to scan: '80', '1-1024', or '22,80,443' (default: 1-1024)")
    ap.add_argument("-t", "--timeout", type=float, default=0.5,
                    help="Per-port timeout in seconds (default: 0.5)")
    ap.add_argument("-w", "--workers", type=int, default=150,
                    help="Concurrent worker threads for socket scan (default: 150)")
    ap.add_argument("--syn", action="store_true",
                    help="Use raw SYN scan via scapy instead of TCP connect scan (needs root)")
    ap.add_argument("-o", "--output", help="Write JSON results to this file")
    args = ap.parse_args()

    try:
        target_ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"ERROR: could not resolve host '{args.target}'", file=sys.stderr)
        sys.exit(1)

    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Target: {args.target} ({target_ip})")
    print(f"Ports:  {len(ports)} port(s) requested")
    print(f"Engine: {'scapy SYN scan' if args.syn else 'socket connect scan'}")
    print("-" * 50)

    start = time.time()
    if args.syn:
        results = run_syn_scan(target_ip, ports, args.timeout)
    else:
        results = run_socket_scan(target_ip, ports, args.timeout, args.workers)
    elapsed = time.time() - start

    print(f"\nScan complete in {elapsed:.2f}s. {len(results)} open port(s) found.\n")
    if results:
        print(f"{'PORT':<8}{'SERVICE':<20}{'BANNER'}")
        print(f"{'-'*8}{'-'*20}{'-'*30}")
        for r in results:
            print(f"{r['port']:<8}{r['service']:<20}{r['banner']}")
    else:
        print("No open ports found in the scanned range.")

    if args.output:
        report = {
            "target": args.target,
            "resolved_ip": target_ip,
            "scan_time_utc": datetime.now(timezone.utc).isoformat(),
            "engine": "scapy_syn" if args.syn else "socket_connect",
            "ports_scanned": len(ports),
            "duration_seconds": round(elapsed, 2),
            "open_ports": results,
        }
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\nJSON report written to {args.output}")


if __name__ == "__main__":
    main()
