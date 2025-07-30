import subprocess
import re
import requests
import time
import os
from fpdf import FPDF
from dotenv import load_dotenv

# Load .env file
load_dotenv()

NVD_API_KEY = os.getenv("NVD_API_KEY")
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

if not NVD_API_KEY:
    print("[-] NVD_API_KEY not found in environment variables. Please set it in your .env file.")
    exit(1)

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

def query_cves(service, version):
    query = f"{service} {version}"
    params = {
        "keywordSearch": query,
        "resultsPerPage": 5,
        "apiKey": NVD_API_KEY
    }
    try:
        response = requests.get(NVD_API_URL, params=params)
        if response.status_code == 200:
            return response.json().get("vulnerabilities", [])
        else:
            print(f"[-] Error querying NVD API ({query}): {response.status_code}")
            return []
    except Exception as e:
        print(f"[-] Exception during API query: {e}")
        return []

def extract_cwe_details(cve_item):
    cve_id = cve_item["cve"]["id"]
    description = cve_item["cve"]["descriptions"][0]["value"]
    cwe_id = cve_item["cve"].get("weaknesses", [{}])[0].get("description", [{}])[0].get("value", "N/A")
    cvss_score = "N/A"

    # Try CVSS v3 first
    metrics = cve_item["cve"].get("metrics", {})
    if "cvssMetricV31" in metrics:
        cvss_score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
    elif "cvssMetricV30" in metrics:
        cvss_score = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
    elif "cvssMetricV2" in metrics:
        cvss_score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

    return {
        "cve_id": cve_id,
        "description": description,
        "cwe_id": cwe_id,
        "cvss_score": cvss_score
    }

def display_findings(services):
    findings = []
    print("\n[!] Vulnerability Report\n")
    for port, service, version in services:
        print(f"\nScanning: {service.upper()} on {port} (version: {version})")
        cve_items = query_cves(service, version)
        time.sleep(1.5)  # NVD rate limit
        for item in cve_items:
            details = extract_cwe_details(item)
            findings.append({
                "port": port,
                "service": service,
                "version": version,
                **details
            })
            print(f"  • CVE: {details['cve_id']}")
            print(f"    CWE: {details['cwe_id']}")
            print(f"    CVSS: {details['cvss_score']}")
            print(f"    Desc: {details['description'][:100]}...")  # Truncate for console
    return findings

def generate_pdf(findings, filename="Vulnerability_Report.pdf"):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "Vulnerability Report", ln=True, align="C")
    pdf.set_font("Arial", "", 11)

    for item in findings:
        pdf.ln(5)
        pdf.multi_cell(0, 10, f"""
[+] {item['service'].upper()} on {item['port']} (version: {item['version']})

- CVE: {item['cve_id']}
- CWE: {item['cwe_id']}
- CVSS Score: {item['cvss_score']}
- Description: {item['description']}
        """)
    pdf.output(filename)
    print(f"\n[+] PDF report generated: {filename}")

if __name__ == "__main__":
    target = input("Enter target IP or domain (e.g., scanme.nmap.org): ").strip()
    nmap_output = run_nmap(target)
    services = extract_services(nmap_output)
    findings = display_findings(services)
    if findings:
        generate_pdf(findings)
    else:
        print("\n[!] No vulnerabilities found or API limits reached.")
