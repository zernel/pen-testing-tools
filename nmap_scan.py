#!/usr/bin/env python3

import argparse
import subprocess
import datetime
import os
import re
import sys
from pathlib import Path

def run_nmap_scan(domain, options=None):
    """
    Execute nmap scan and return results
    """
    if options is None:
        options = ["-sV", "-sC", "--script=vuln"]
    
    cmd = ["nmap"] + options + [domain]
    print(f"Executing command: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error executing nmap scan: {e}")
        print(f"Error output: {e.stderr}")
        sys.exit(1)

def parse_nmap_output(output):
    """
    Parse nmap output and extract port, service and vulnerability information
    """
    data = {
        'ports': [],
        'vulnerabilities': []
    }
    
    # Extract open ports and service information
    port_pattern = re.compile(r'(\d+)/(tcp|udp)\s+(open|filtered|closed)\s+(.+)')
    for line in output.splitlines():
        match = port_pattern.search(line)
        if match:
            port_num, protocol, state, service_info = match.groups()
            data['ports'].append({
                'port': port_num,
                'protocol': protocol,
                'state': state,
                'service': service_info.strip()
            })
    
    # Extract vulnerability information
    vuln_pattern = re.compile(r'(CVE-\d+-\d+).*?(\d+\.\d+)')
    in_vuln_section = False
    current_vuln = {}
    
    for line in output.splitlines():
        if '| vulners:' in line or '|_http-vuln' in line:
            in_vuln_section = True
        elif in_vuln_section and line.strip().startswith('|'):
            vuln_match = vuln_pattern.search(line)
            if vuln_match:
                cve_id, severity = vuln_match.groups()
                description = line.strip('| \t')
                data['vulnerabilities'].append({
                    'cve_id': cve_id,
                    'severity': severity,
                    'description': description
                })
        elif in_vuln_section and not line.strip().startswith('|'):
            in_vuln_section = False
    
    return data

def generate_report(domain, scan_results, raw_output, output_path):
    """
    Generate Markdown-formatted report
    """
    now = datetime.datetime.now()
    timestamp = now.strftime("%Y%m%d_%H%M%S")
    
    # Create report directory
    report_dir = Path(output_path) / domain
    report_dir.mkdir(parents=True, exist_ok=True)
    
    report_file = report_dir / f"nmap-{timestamp}.md"
    
    with report_file.open("w") as f:
        f.write(f"# Nmap Scan Report: {domain}\n\n")
        f.write(f"**Scan Time**: {now.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        # Port and service information
        f.write("## Open Ports and Services\n\n")
        if scan_results['ports']:
            f.write("| Port | Protocol | State | Service |\n")
            f.write("|------|----------|-------|--------|\n")
            for port in scan_results['ports']:
                f.write(f"| {port['port']} | {port['protocol']} | {port['state']} | {port['service']} |\n")
        else:
            f.write("No open ports discovered\n")
        
        # Vulnerability information
        f.write("\n## Security Risk Analysis\n\n")
        if scan_results['vulnerabilities']:
            f.write("| CVE ID | Severity | Description |\n")
            f.write("|--------|----------|-------------|\n")
            for vuln in scan_results['vulnerabilities']:
                f.write(f"| {vuln['cve_id']} | {vuln['severity']} | {vuln['description']} |\n")
            
            # Calculate risk level
            try:
                high_risk = sum(1 for v in scan_results['vulnerabilities'] 
                               if float(v['severity']) >= 7.0)
                medium_risk = sum(1 for v in scan_results['vulnerabilities'] 
                                 if 4.0 <= float(v['severity']) < 7.0)
                low_risk = sum(1 for v in scan_results['vulnerabilities'] 
                              if float(v['severity']) < 4.0)
                
                f.write("\n### Risk Summary\n\n")
                f.write(f"- High Risk Vulnerabilities: {high_risk}\n")
                f.write(f"- Medium Risk Vulnerabilities: {medium_risk}\n")
                f.write(f"- Low Risk Vulnerabilities: {low_risk}\n")
                
                risk_level = "Low"
                if high_risk > 0:
                    risk_level = "High"
                elif medium_risk > 0:
                    risk_level = "Medium"
                    
                f.write(f"\nOverall Security Risk: **{risk_level}**\n")
            except:
                f.write("\nUnable to determine risk level\n")
        else:
            f.write("No obvious security risks found\n")
        
        # Raw scan results
        f.write("\n## Raw Scan Results\n\n")
        f.write("```\n")
        f.write(raw_output)
        f.write("\n```\n")
    
    return report_file

def main():
    parser = argparse.ArgumentParser(description="Scan a domain with nmap and generate a security analysis report")
    parser.add_argument("domain", help="Domain name or IP address to scan")
    parser.add_argument("--output", "-o", default="reports", help="Output directory for reports")
    parser.add_argument("--scan-type", "-t", choices=["basic", "full", "vuln"], default="vuln",
                       help="Scan type: basic (basic port scan), full (complete port scan), vuln (vulnerability scan)")
    
    args = parser.parse_args()
    
    # Choose nmap options based on scan type
    scan_options = {
        "basic": ["-sV"],
        "full": ["-sV", "-p-"],
        "vuln": ["-sV", "-sC", "--script=vuln"]
    }
    
    print(f"Starting scan of domain: {args.domain}")
    print(f"Scan type: {args.scan_type}")
    
    # Execute nmap scan
    scan_output = run_nmap_scan(args.domain, scan_options[args.scan_type])
    
    # Parse results
    scan_results = parse_nmap_output(scan_output)
    
    # Generate report
    report_file = generate_report(args.domain, scan_results, scan_output, args.output)
    
    print(f"Scan complete! Report saved to: {report_file}")

if __name__ == "__main__":
    main()
