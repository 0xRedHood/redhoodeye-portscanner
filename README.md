# RedhoodEye - Advanced Network Scanner

A professional network scanner with advanced features - everything in one file!

## Features

- **Multi-threaded scanning** with intelligent thread management
- **Banner grabbing** from open ports
- **Service detection** for common ports
- **Colored output** with beautiful formatting
- **Advanced logging** with file rotation
- **IPv4 and IPv6 support**
- **Predefined port sets** for common services
- **Multiple output formats**: JSON, CSV, HTML
- **Detailed statistics** and reporting
- **System information tool** with WHOIS lookup and network diagnostics
- **UDP scanning** for UDP service detection
- **Stealth scanning** with rate limiting and port randomization
- **Enhanced service detection** with improved version detection
- **Advanced service detection** with protocol analysis and version extraction
- **Multiple target support** with CIDR ranges and target files
- **Improved UDP scanning** with protocol-specific probes
- **HTTP/HTTPS Proxy support** for bypassing firewalls
- **SOCKS4/SOCKS5 Proxy support** for anonymous scanning
- **Scheduled scanning** with cron-like syntax
- **Background job management** for continuous monitoring

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### Basic scan
```bash
python RedhoodEye.py --target 192.168.1.1
```

### Scan specific ports
```bash
python RedhoodEye.py --target example.com --ports 80,443,8080
```

### Scan with predefined port sets
```bash
python RedhoodEye.py --target 192.168.1.1 --ports web
python RedhoodEye.py --target 192.168.1.1 --ports database
python RedhoodEye.py --target 192.168.1.1 --ports remote
```

### Scan with logging
```bash
python RedhoodEye.py --target 192.168.1.1 --log-file scan.log --log-level DEBUG
```

### Scan without colors
```bash
python RedhoodEye.py --target 192.168.1.1 --no-colors
```

### System information and WHOIS lookup
```bash
python RedhoodEye.py --target google.com --how-is
python RedhoodEye.py --target 192.168.1.1 --how-is --ports 80-443
python RedhoodEye.py --target google.com --how-is --no-port-check
```

### UDP scanning
```bash
python RedhoodEye.py --target 192.168.1.1 --scan-type udp --ports 53,123,161
python RedhoodEye.py --target 192.168.1.1 --scan-type udp --ports 1-1024
```

### Stealth scanning
```bash
python RedhoodEye.py --target 192.168.1.1 --rate-limit 10 --randomize
python RedhoodEye.py --target 192.168.1.1 --show-closed --verbose
```

### Multiple targets
```bash
python RedhoodEye.py --cidr 192.168.1.0/24 --ports 80,443
python RedhoodEye.py --target-file targets.txt --ports web
python RedhoodEye.py --target-file hosts.txt --scan-type udp --ports 53,123,161
```

### Display options
```bash
python RedhoodEye.py --target 192.168.1.1 --no-banner
python RedhoodEye.py --target 192.168.1.1 --no-colors
```

### Proxy scanning
```bash
python RedhoodEye.py --target 192.168.1.1 --proxy http://proxy:8080
python RedhoodEye.py --target 192.168.1.1 --proxy socks5://proxy:1080
python RedhoodEye.py --target 192.168.1.1 --proxy http://proxy:8080 --proxy-auth user:pass
```

### Scheduled scanning
```bash
python RedhoodEye.py --target 192.168.1.1 --schedule "0 2 * * *" --job-id daily_scan
python RedhoodEye.py --target 192.168.1.1 --schedule daily --job-id daily_scan
python RedhoodEye.py --target 192.168.1.1 --schedule hourly --job-id hourly_scan
python RedhoodEye.py --list-jobs
python RedhoodEye.py --remove-job daily_scan
```

## Port Sets

| Set | Description | Ports |
|-----|-------------|-------|
| `web` | Web services | 80, 443, 8080, 8443, 3000, 5000, 8000, 9000 |
| `database` | Database services | 3306, 5432, 6379, 27017, 1433, 1521, 2181 |
| `remote` | Remote access | 22, 23, 3389, 5900, 5901, 5902, 5903 |
| `email` | Email services | 25, 110, 143, 465, 587, 993, 995 |
| `common` | Common services | 21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017 |
| `all` | All ports | 1-65535 |

## Colored Output

- **Green**: Success messages
- **Blue**: Statistics and progress
- **Yellow**: Warnings
- **Red**: Errors
- **Magenta**: Banner information
- **White**: Headers

## Example Output

### Port Scan Output
```
STARTING PORT SCAN
Target: 192.168.1.1
Ports: 1000 ports
Threads: 100
Timeout: 3s
============================================================
Progress: 100.0% (1000/1000)
============================================================
Scan completed in 12.34 seconds
Found 2 open ports out of 1000 scanned
============================================================
PERFORMANCE METRICS
   ports_per_second: 81.04
   open_percentage: 0.20
   error_percentage: 0.00
```

### System Information Output
```
Target System Information
===========================================================
Target: 142.250.179.110
Reverse DNS: 142.250.179.110 -> par21s20-in-f14.1e100.net
Ping test: SUCCESS
Ping time: 86ms
WHOIS Record:
  # ARIN WHOIS data and services are subject to the Terms of Use
  # Copyright 1997-2025, American Registry for Internet Numbers, Ltd.
  # ...
===========================================================
Target system information check completed
```

## Cross-Platform Support

This tool is designed to work across different operating systems:

- **Windows**: Uses `ping -n`, `ipconfig`, `route print`
- **macOS**: Uses `ping -c`, `ifconfig`, `netstat -rn`
- **Linux**: Uses `ping -c`, `ip addr`, `ip route` with fallback to `ifconfig` and `netstat -rn`

The tool automatically detects the operating system and uses appropriate commands.

## Security Warning

This tool is for educational and authorized testing purposes only. Only scan systems you own or have explicit permission to test.

## License

This tool is provided for educational purposes. Use responsibly and only on systems you own or have permission to test. 