Port Scanner & Service Identifier, a lightweight Python tool that scans a target host for open TCP ports and identifies the services running on them, built as the foundation for a network/tech audit workflow.
```
Target: 192.168.1.10 (192.168.1.10)
Ports:  1024 port(s) requested
Engine: socket connect scan
--------------------------------------------------
Scan complete in 4.12s. 9 open port(s) found.

PORT    SERVICE             BANNER
--------------------------------------------------------
25      SMTP                220 mail.local ESMTP ready
110     POP3
119     NNTP
143     IMAP
465     SMTPS               TLSv1.2 | CN=mail.local
563     NNTPS
587     SMTP-Submission
993     IMAPS               TLSv1.3 | CN=mail.local | * OK IMAPS4rev1 ready
995     POP3S               TLSv1.3 | CN=mail.local | +OK POP3 ready
```
Why I built this. Port scanning is one of the first steps in any network security audit or asset inventory, knowing what's actually listening on a host tells you a lot more than a hostname or IP address alone. I wanted a tool that goes beyond a bare open/closed port list and actually tries to identify what is running, including grabbing real banners from encrypted services via a TLS handshake.
Features: Two scan engines. The default socket engine performs a TCP connect scan, is multithreaded, and doesn't need special privileges. The scapy engine, used with --syn, does a raw SYN scan; it's faster and stealthier but requires scapy and root or admin rights. Service identification uses a common-ports lookup table that covers SSH, HTTP, RDP, MySQL, Redis, Elasticsearch, and more, and it also grabs live banners. TLS-aware banner grabbing works for implicit-TLS ports like 443, 465, 993, 995, 8443, and 3269. In those cases the scanner does a real TLS handshake and reports the negotiated TLS version, the certificate common name, and any post-handshake greeting. Flexible port specification allows single ports, ranges, or comma-separated lists such as 22,80,443,8000-8100. Finally, the tool can export results in JSON for feeding into other tools or archiving audit history.
Requirements
Python 3.8+
`scapy` — only required for `--syn` mode
```bash
pip install -r requirements.txt
```
Usage
```bash
# Default scan of the first 1024 ports
python3 port_scanner.py 192.168.1.10

# Specific ports
python3 port_scanner.py 192.168.1.10 -p 22,80,443,8080

# A range, with more threads and a shorter timeout for speed
python3 port_scanner.py 192.168.1.10 -p 1-65535 -t 0.3 -w 300

# Raw SYN scan (needs scapy + root/admin)
sudo python3 port_scanner.py 192.168.1.10 --syn -p 1-1024

# Save results as JSON for an audit report
python3 port_scanner.py 192.168.1.10 -o audit_report.json
```
Options
Flag	Description	Default
`-p`, `--ports`	Ports to scan: `80`, `1-1024`, or `22,80,443`	`1-1024`
`-t`, `--timeout`	Per-port timeout in seconds	`0.5`
`-w`, `--workers`	Concurrent threads (socket scan only)	`150`
`--syn`	Use a raw SYN scan via scapy instead of a TCP connect scan	off
`-o`, `--output`	Write results to a JSON file	none
How it works
The tool resolves the target hostname to an IP address. It parses the requested port specification into a sorted list. For each port, it either opens a TCP connection and reads/sends a small probe to grab a banner (socket mode), or sends a raw SYN packet and inspects the response flags (scapy mode, SYN scan). For ports that speak TLS immediately on connect (like 465/993/995), it performs a TLS handshake instead of a plaintext read and reports the TLS version and certificate CN alongside any greeting. The banner text and/or port number is matched against a lookup table to label the likely service. A summary table is printed, and, if requested, a JSON report is written.

Responsible use
This tool is intended for authorized network audits, asset discovery, and learning purposes only. Only scan hosts and networks you own or have explicit written permission to test. Unauthorized port scanning can violate computer-use laws (e.g., the U.S. Computer Fraud and Abuse Act) even when the tool itself is benign.

Roadmap / ideas
UDP scanning, OS fingerprinting (TTL, window size), CSV export for compliance reporting, concurrent TLS handshakes to speed up encrypted-port scanning.eed up encrypted-port scanning
License
MIT — see LICENSE.
