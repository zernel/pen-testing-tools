# Pen Testing Tools

| Name                                            | Type                    | Description                                                                                                 |
| ----------------------------------------------- | ----------------------- | ----------------------------------------------------------------------------------------------------------- |
| nmap                                            | Port Scanner            | This port scanner is used to determine running services and is suitable for long-duration scans with various timing settings. |
| Nessus                                          | Vulnerability Scanner   | Scanner used to identify known vulnerabilities and misconfigurations.                                        |
| ike-scan                                        | IPSec Gateway Scanner   | Tests IPSec gateways for misconfigurations.                                                                 |
| Burp Suite Pro                                  | Man-in-the-middle Web Proxy and Web Application Analysis Tool | Framework for testing web applications via "intercepting" proxy and various attack modules.          |
| Metasploit                                      | Attack Framework        | This framework provides exploits against vulnerable systems, potentially gaining full administrative access. |
| sqlmap                                          | SQL Injection Tool      | Used to find SQL injection vulnerabilities in web applications.                                              |
| nikto                                           | Web Application Analysis Tool | Web servers often provide numerous vulnerable and exploitable modules and routines. Nikto is used to identify these routines for subsequent attacks. |
| Firefox + Firebug, Developer Tools & Tamperdata | HTTP Communication Analysis and Modification | Firefox browser plugins for analyzing and modifying HTTP communications.                           |
| Common Standard Tools                           | Standard Tools          | For general work, e.g., bash shell, telnet, netcat, traceroute, Firefox, Microsoft resource kits, Internet Explorer, Notepad, etc. |

## nmap
nmap is a powerful network scanning tool that can be used to discover network hosts, identify services, and perform security scans. We have developed a Python wrapper script that automates common scanning tasks and generates reports.

### nmap_scan.py Script

This script performs automated scans and generates Markdown-formatted reports.

**Usage**:
```bash
python3 nmap_scan.py example.com
```

**Optional arguments**:
- `--output` or `-o`: Specify report save location (defaults to reports directory)
- `--scan-type` or `-t`: Specify scan type, options are basic, full, or vuln (vulnerability scan)

**Features**:
1. Scan target domain or IP for open ports
2. Identify running services
3. Detect potential security vulnerabilities
4. Generate detailed analysis reports
