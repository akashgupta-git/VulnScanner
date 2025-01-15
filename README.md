# VulnScanner

A simple Python-based vulnerability scanner that uses Nmap to detect open ports and running services on a target system.

## Features
- Accepts a domain or IP as input
- Runs an `nmap -sV` scan
- Parses output to extract service version info
- Flags services to check manually on CVE websites

## How to Use
1. Install `nmap`
2. Run the script:
python vulnscanner.py

3. Input a target (example: `scanme.nmap.org`)
4. Check listed services for vulnerabilities on https://cve.mitre.org

## Example Output
[+] Running Nmap scan on scanme.nmap.org...

PORT STATE SERVICE VERSION
22/tcp open ssh OpenSSH 7.6p1 Ubuntu
80/tcp open http Apache httpd 2.4.29

[!] Potentially vulnerable services (check versions):

SSH on 22/tcp (version: OpenSSH 7.6p1 Ubuntu) — Google for CVEs
HTTP on 80/tcp (version: Apache httpd 2.4.29) — Google for CVEs

## Disclaimer
Use only for ethical, educational purposes. Do not scan unauthorized systems.