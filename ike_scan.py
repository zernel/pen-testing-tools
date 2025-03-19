#!/usr/bin/env python3

import argparse
import subprocess
import datetime
import os
import re
import sys
from pathlib import Path

def run_ike_scan(domain, options=None):
    """
    Execute ike-scan and return results
    """
    if options is None:
        options = ["--showbackoff"]  # Removed unsupported --multikey option
    
    cmd = ["ike-scan"] + options + [domain]
    print(f"Executing command: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error executing ike-scan: {e}")
        print(f"Error output: {e.stderr}")
        
        # Check if there's help available and suggest to the user
        try:
            help_result = subprocess.run(["ike-scan", "--help"], capture_output=True, text=True)
            print("\nTry running 'ike-scan --help' to see available options for your version.")
        except:
            pass
        
        sys.exit(1)

def parse_ike_scan_output(output):
    """
    Parse ike-scan output and extract relevant information
    """
    data = {
        'hosts': [],
        'handshake': False,
        'supported_transforms': [],
        'backoff_pattern': None
    }
    
    lines = output.splitlines()
    current_host = None
    
    for line in lines:
        # Check for discovered hosts
        host_match = re.search(r'(\d+\.\d+\.\d+\.\d+|[\w\.-]+):(\d+)', line)
        if host_match:
            host = host_match.group(1)
            port = host_match.group(2)
            current_host = {'host': host, 'port': port, 'status': 'unknown'}
            data['hosts'].append(current_host)
        
        # Check for handshake status
        if current_host and "Handshake returned" in line:
            current_host['status'] = 'handshake_successful'
            data['handshake'] = True
        elif current_host and "No response" in line:
            current_host['status'] = 'no_response'
        
        # Check for supported transforms
        transform_match = re.search(r'SA=(\w+) (.+)', line)
        if transform_match:
            transform_type = transform_match.group(1)
            transform_details = transform_match.group(2)
            data['supported_transforms'].append({
                'type': transform_type,
                'details': transform_details
            })
        
        # Check for backoff pattern
        if "Backoff" in line:
            data['backoff_pattern'] = line.strip()
    
    return data

def assess_security_risks(scan_data):
    """
    Assess security risks based on scan data
    """
    risks = []
    
    # Check if service is detected
    if scan_data['handshake']:
        risks.append({
            'level': 'Info',
            'description': 'IPSec VPN service detected.'
        })
    
    # Check for weak transforms
    weak_encryptions = ['DES', 'NULL']
    weak_hashes = ['MD5', 'NULL']
    
    for transform in scan_data['supported_transforms']:
        for weak_enc in weak_encryptions:
            if f"Enc={weak_enc}" in transform['details']:
                risks.append({
                    'level': 'High',
                    'description': f"Weak encryption algorithm detected: {weak_enc}"
                })
        
        for weak_hash in weak_hashes:
            if f"Hash={weak_hash}" in transform['details']:
                risks.append({
                    'level': 'Medium',
                    'description': f"Weak hash algorithm detected: {weak_hash}"
                })
            
        if "Auth=PSK" in transform['details']:
            risks.append({
                'level': 'Low',
                'description': "Pre-Shared Key authentication detected (consider using certificate-based authentication)."
            })
        
        if "Group=1" in transform['details'] or "Group=2" in transform['details']:
            risks.append({
                'level': 'High',
                'description': f"Weak Diffie-Hellman group detected: {transform['details']}"
            })
    
    # Assess overall risk
    risk_level = "Low"
    if any(r['level'] == 'High' for r in risks):
        risk_level = "High"
    elif any(r['level'] == 'Medium' for r in risks):
        risk_level = "Medium"
    
    return {'risks': risks, 'overall_level': risk_level}

def generate_report(domain, scan_data, risk_assessment, raw_output, output_path):
    """
    Generate Markdown-formatted report
    """
    now = datetime.datetime.now()
    timestamp = now.strftime("%Y%m%d_%H%M%S")
    
    # Create report directory
    report_dir = Path(output_path) / domain
    report_dir.mkdir(parents=True, exist_ok=True)
    
    report_file = report_dir / f"ike-scan-{timestamp}.md"
    
    with report_file.open("w") as f:
        f.write(f"# IKE-Scan Report: {domain}\n\n")
        f.write(f"**Scan Time**: {now.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        # Host Information
        f.write("## Host Information\n\n")
        if scan_data['hosts']:
            f.write("| Host | Port | Status |\n")
            f.write("|------|------|--------|\n")
            for host in scan_data['hosts']:
                status = host['status'].replace('_', ' ').title()
                f.write(f"| {host['host']} | {host['port']} | {status} |\n")
        else:
            f.write("No hosts responded to IKE requests\n")
        
        # Transform Information
        f.write("\n## Supported Transforms\n\n")
        if scan_data['supported_transforms']:
            f.write("| Type | Details |\n")
            f.write("|------|--------|\n")
            for transform in scan_data['supported_transforms']:
                f.write(f"| {transform['type']} | {transform['details']} |\n")
        else:
            f.write("No transform information available\n")
        
        # Backoff Pattern
        if scan_data['backoff_pattern']:
            f.write("\n## Backoff Pattern\n\n")
            f.write(f"```\n{scan_data['backoff_pattern']}\n```\n")
        
        # Security Risk Analysis
        f.write("\n## Security Risk Analysis\n\n")
        if risk_assessment['risks']:
            f.write("| Risk Level | Description |\n")
            f.write("|------------|-------------|\n")
            for risk in risk_assessment['risks']:
                f.write(f"| {risk['level']} | {risk['description']} |\n")
            
            f.write("\n### Risk Summary\n\n")
            high_risks = sum(1 for r in risk_assessment['risks'] if r['level'] == 'High')
            medium_risks = sum(1 for r in risk_assessment['risks'] if r['level'] == 'Medium')
            low_risks = sum(1 for r in risk_assessment['risks'] if r['level'] == 'Low')
            
            f.write(f"- High Risk Issues: {high_risks}\n")
            f.write(f"- Medium Risk Issues: {medium_risks}\n")
            f.write(f"- Low Risk Issues: {low_risks}\n")
            f.write(f"\nOverall Security Risk: **{risk_assessment['overall_level']}**\n")
        else:
            f.write("No security risks identified\n")
        
        # Raw scan results
        f.write("\n## Raw Scan Results\n\n")
        f.write("```\n")
        f.write(raw_output)
        f.write("\n```\n")
    
    return report_file

def main():
    parser = argparse.ArgumentParser(description="Scan a domain with ike-scan for IPSec VPN services and generate a security analysis report")
    parser.add_argument("domain", help="Domain name or IP address to scan")
    parser.add_argument("--output", "-o", default="reports", help="Output directory for reports")
    parser.add_argument("--aggressive", "-a", action="store_true", help="Use aggressive scanning mode")
    parser.add_argument("--timeout", "-t", type=int, default=5, help="Timeout in seconds (default: 5)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    
    args = parser.parse_args()
    
    # Set scan options with supported parameters only
    scan_options = ["--showbackoff"]
    
    # Add timeout option
    scan_options.append(f"--timeout={args.timeout}")
    
    # Add other supported options
    if args.aggressive:
        scan_options.append("--aggressive")
    
    if args.verbose:
        scan_options.append("--verbose")
    
    print(f"Starting IPSec scan of domain: {args.domain}")
    
    # Execute ike-scan
    scan_output = run_ike_scan(args.domain, scan_options)
    
    # Parse results
    scan_data = parse_ike_scan_output(scan_output)
    
    # Assess security risks
    risk_assessment = assess_security_risks(scan_data)
    
    # Generate report
    report_file = generate_report(args.domain, scan_data, risk_assessment, scan_output, args.output)
    
    print(f"Scan complete! Report saved to: {report_file}")

if __name__ == "__main__":
    main()
