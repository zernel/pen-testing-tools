# Pen Testing Tools

| 名称                                              | 类型                     | 描述                                                                                                 |
| ----------------------------------------------- | ---------------------- | -------------------------------------------------------------------------------------------------- |
| nmap                                            | 端口扫描器                  | 该端口扫描器用于确定运行的服务，并通过各种定时设置适合长时间扫描。                                                                  |
| Nessus                                          | 漏洞扫描器                  | 用于识别已知漏洞和错误配置的扫描器。                                                                                 |
| ike-scan                                        | IPSec 网关扫描器            | 测试 IPSec 网关的错误配置。                                                                                  |
| Burp Suite Pro                                  | 中间人 Web 代理和 Web 应用分析工具 | 通过“拦截”代理和各种攻击模块测试 Web 应用的框架。                                                                       |
| Metasploit                                      | 攻击框架                   | 该框架提供了针对易受攻击系统的漏洞利用，可能获得完全的管理权限。                                                                   |
| sqlmap                                          | SQL 注入工具               | 用于在 Web 应用中查找 SQL 注入漏洞。                                                                            |
| nikto                                           | Web 应用分析工具             | Web 服务器通常提供许多漏洞和可攻击的模块和例程。Nikto 用于识别这些例程，以便后续攻击。                                                   |
| Firefox + Firebug, Developer Tools & Tamperdata | HTTP 通信分析和修改           | Firefox 浏览器插件，用于分析和修改 HTTP 通信。                                                                     |
| 常用标准工具                                          | 标准工具                   | 用于一般工作，例如 bash shell、telnet、netcat、traceroute、Firefox、Microsoft 资源工具包、Internet Explorer、Notepad 等。 |## nmap
nmap 是一款功能强大的网络扫描工具，可用于发现网络主机、服务识别和安全扫描。我们已经开发了一个Python包装脚本，可以自动执行常见扫描任务并生成报告。

### nmap_scan.py 脚本

此脚本可以执行自动化扫描并生成Markdown格式的报告。

**用法**:
```bash
python3 nmap_scan.py example.com
```

**可选参数**:
- `--output` 或 `-o`: 指定报告保存路径（默认为reports目录）
- `--scan-type` 或 `-t`: 指定扫描类型，可选basic（基本）、full（完整）或vuln（漏洞扫描）

**功能**:
1. 扫描目标域名或IP的开放端口
2. 识别运行的服务
3. 检测潜在的安全漏洞
4. 生成详细的分析报告
