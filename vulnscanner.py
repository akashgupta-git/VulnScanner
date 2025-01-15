import subprocess
import re

def run_nmap(target):
    print(f"\n[+] Running Nmap scan on {target}...\n")
    result = subprocess.run(['nmap', '-sV', target], capture_output=True, text=True)
    return result.stdout

def extract_services(nmap_output):
    services = []
    lines = nmap_output.splitlines()
    for line in lines:
        match = re.match(r"(\d+/tcp)\s+open\s+(\S+)\s+(.+)", line)
        if match:
            port, service, version = match.groups()
            services.append((port, service, version))
    return services

def display_findings(services):
    print("\n[!] Potentially vulnerable services (check versions):\n")
    for port, service, version in services:
        print(f"- {service.upper()} on {port} (version: {version}) — Google for CVEs")

if __name__ == "__main__":
    target = input("Enter target IP or domain (e.g., scanme.nmap.org): ").strip()
    output = run_nmap(target)
    services = extract_services(output)
    display_findings(services)
