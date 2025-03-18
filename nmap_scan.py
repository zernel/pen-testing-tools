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
    执行nmap扫描并返回结果
    """
    if options is None:
        options = ["-sV", "-sC", "--script=vuln"]
    
    cmd = ["nmap"] + options + [domain]
    print(f"执行命令: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"执行nmap扫描时出错: {e}")
        print(f"错误输出: {e.stderr}")
        sys.exit(1)

def parse_nmap_output(output):
    """
    解析nmap输出并提取端口、服务和漏洞信息
    """
    data = {
        'ports': [],
        'vulnerabilities': []
    }
    
    # 提取开放端口和服务信息
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
    
    # 提取漏洞信息
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
    生成Markdown格式的报告
    """
    now = datetime.datetime.now()
    timestamp = now.strftime("%Y%m%d_%H%M%S")
    
    # 创建报告目录
    report_dir = Path(output_path) / domain
    report_dir.mkdir(parents=True, exist_ok=True)
    
    report_file = report_dir / f"nmap-{timestamp}.md"
    
    with report_file.open("w") as f:
        f.write(f"# Nmap 扫描报告: {domain}\n\n")
        f.write(f"**扫描时间**: {now.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        # 端口和服务信息
        f.write("## 开放端口和服务\n\n")
        if scan_results['ports']:
            f.write("| 端口 | 协议 | 状态 | 服务 |\n")
            f.write("|------|------|------|------|\n")
            for port in scan_results['ports']:
                f.write(f"| {port['port']} | {port['protocol']} | {port['state']} | {port['service']} |\n")
        else:
            f.write("未发现开放端口\n")
        
        # 漏洞信息
        f.write("\n## 安全风险分析\n\n")
        if scan_results['vulnerabilities']:
            f.write("| CVE ID | 严重程度 | 描述 |\n")
            f.write("|--------|----------|------|\n")
            for vuln in scan_results['vulnerabilities']:
                f.write(f"| {vuln['cve_id']} | {vuln['severity']} | {vuln['description']} |\n")
            
            # 计算风险等级
            try:
                high_risk = sum(1 for v in scan_results['vulnerabilities'] 
                               if float(v['severity']) >= 7.0)
                medium_risk = sum(1 for v in scan_results['vulnerabilities'] 
                                 if 4.0 <= float(v['severity']) < 7.0)
                low_risk = sum(1 for v in scan_results['vulnerabilities'] 
                              if float(v['severity']) < 4.0)
                
                f.write("\n### 风险总结\n\n")
                f.write(f"- 高风险漏洞: {high_risk}\n")
                f.write(f"- 中风险漏洞: {medium_risk}\n")
                f.write(f"- 低风险漏洞: {low_risk}\n")
                
                risk_level = "低"
                if high_risk > 0:
                    risk_level = "高"
                elif medium_risk > 0:
                    risk_level = "中"
                    
                f.write(f"\n总体安全风险: **{risk_level}**\n")
            except:
                f.write("\n无法确定风险等级\n")
        else:
            f.write("未发现明显安全风险\n")
        
        # 原始扫描结果
        f.write("\n## 原始扫描结果\n\n")
        f.write("```\n")
        f.write(raw_output)
        f.write("\n```\n")
    
    return report_file

def main():
    parser = argparse.ArgumentParser(description="使用nmap扫描域名并生成安全分析报告")
    parser.add_argument("domain", help="要扫描的域名或IP地址")
    parser.add_argument("--output", "-o", default="reports", help="报告输出目录")
    parser.add_argument("--scan-type", "-t", choices=["basic", "full", "vuln"], default="vuln",
                       help="扫描类型: basic(基础端口扫描), full(完整端口扫描), vuln(漏洞扫描)")
    
    args = parser.parse_args()
    
    # 根据扫描类型选择nmap选项
    scan_options = {
        "basic": ["-sV"],
        "full": ["-sV", "-p-"],
        "vuln": ["-sV", "-sC", "--script=vuln"]
    }
    
    print(f"开始扫描域名: {args.domain}")
    print(f"扫描类型: {args.scan_type}")
    
    # 执行nmap扫描
    scan_output = run_nmap_scan(args.domain, scan_options[args.scan_type])
    
    # 解析结果
    scan_results = parse_nmap_output(scan_output)
    
    # 生成报告
    report_file = generate_report(args.domain, scan_results, scan_output, args.output)
    
    print(f"扫描完成! 报告已保存至: {report_file}")

if __name__ == "__main__":
    main()
