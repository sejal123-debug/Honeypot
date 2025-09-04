# Honeypot

# Honeypie: Multi-Service Honeypot Framework

![Python](https://img.shields.io/badge/Python-3.13.5-blue)
![SSH](https://img.shields.io/badge/Service-SSH-orange)
![HTTP](https://img.shields.io/badge/Service-HTTP-red)
![FTP](https://img.shields.io/badge/Service-FTP-blue)


## 🌟 Features

- **Service**: SSH, HTTP, and FTP honeypots in a single framework
- **Emulation**:  service responses and system environments
- **Advanced Logging**: Structured JSON logging with session tracking and forensic capabilities
- **Threat Detection**: Suspicious activity monitoring and data exfiltration detection
- **Customizable**: Configurable ports, credentials, and security policies
- **Deception Techniques**: Honeytokens, fake filesystems, and anti-crawler measures

## 📦 Installation

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd honeypie
   ```
2. If you’re inside a virtual environment (recommended)
   ```
   python3 -m venv venv
   source venv/bin/activate   # Linux/macOS
   venv\Scripts\activate      # Windows PowerShell
   pip install -r requirements.txt
   ```

   ⚠️ Make sure you’re using a Python version supported by the packages (paramiko==3.4.0, cryptography==42.0.5 both work fine on Python 3.8+).

3. **Install dependencies**:
   ```
   pip install paramiko
   ```

4. **Run the honeypot**:
   ```
   python argparseHoney.py [service] [options]
   ```

## 🚀 Quick Start

### SSH Honeypot
```bash
python argparseHoney.py ssh -p 2222 -u admin -pw password (or)
python argparseHoney.py ssh -p 2222
```

### HTTP Honeypot
```bash
python argparseHoney.py http -p 8080 -u admin -pw password (or)
python argparseHoney.py http -p 8080
```

### FTP Honeypot
```bash
python argparseHoney.py ftp -p 2121 -u anonymous -pw "" (or)
python argparseHoney.py ftp -p 2121
```

## 🛠️ Usage

### Command Line Arguments

```
usage: argparseHoney.py [-h] [-a ADDRESS] {ssh,http,ftp} ...

positional arguments:
  {ssh,http,ftp}        Type of honeypot service to run
    ssh                 Run the SSH honeypot service
    http                Run the HTTP (Web) honeypot service
    ftp                 Run the FTP honeypot service

optional arguments:
  -h, --help            show this help message and exit
  -a ADDRESS, --address ADDRESS
                        The IP address to bind to (default: 0.0.0.0)
```

### Service-Specific Options

#### SSH Options
```
-p PORT, --port PORT    Port to listen on (default: 2222)
-u USERNAME, --username USERNAME
                        A specific username to accept (accepts any if not set)
-pw PASSWORD, --password PASSWORD
                        A specific password to accept (accepts any if not set)
```
Test
```
ssh test@<ip-address> -p 2222  (or)
ssh -o StrictHostKeyChecking=no test@<ip-address> -p 2222
```
#### HTTP Options
```
-p PORT, --port PORT    Port to listen on (default: 8080)
-u USERNAME, --username USERNAME
                        Username to present on the login page (default: admin)
-pw PASSWORD, --password PASSWORD
                        Password to present on the login page (default: password)
```

#### FTP Options
```
-p PORT, --port PORT    Port to listen on (default: 2121)
-u USERNAME, --username USERNAME
                        A specific username to accept (accepts any if not set)
-pw PASSWORD, --password PASSWORD
                        A specific password to accept (accepts any if not set)
```
Test
```
ftp <ip-address> 
(or)
ftp
open <ip-address> 2121
```

## 📋 Services Overview

### SSH
- Emulates a complete Linux shell environment
- Supports 50+ common commands (ls, cat, ps, whoami, etc.)
- Fake filesystem with realistic directory structure
- Session persistence tracking and command history

### HTTP Honeypot
- Fake admin login page with credential capture
- Client-side protection
- UI design for credibility

### FTP Honeypot
- Fake filesystem with believable content
- Full FTP command support (LIST, RETR, STOR, etc.)
- Data exfiltration monitoring and large transfer detection
- Brute-force protection with IP banning

## 📊 Logging and Monitoring

The honeypot provides logging system:

1. **Unified Logs**: `honeypot.log` - Combined logs from all services
2. **Structured Logs**: `ftp_honeypot_structured.log` - JSON-formatted detailed logs
3. **Session Logs**: Individual session files for forensic analysis

### Log Format
```
[timestamp] [LEVEL] [SERVICE] message
[2023-11-15T14:30:45.123Z] [INFO] [SSH] SSH auth from 192.168.1.100:54321 username='admin' password='***'
```

### Sample Output
```
[+] SSH Honeypot listening on 0.0.0.0:2222
[i] Accepting password auth for username=admin, password=***
SSH connection from 192.168.1.100:54321
SSH auth from 192.168.1.100:54321 username='admin' password='***'
```

## 🔍 Detection Capabilities

The honeypot detects and logs:
- Brute-force authentication attempts
- Suspicious command execution
- Data exfiltration attempts
- Access to sensitive paths (/etc/passwd, /root, etc.)
- Large file transfers (>1MB)
- Command injection attempts

## 🏗️ Architecture

```
honeypie/
├── argparseHoney.py      # Main entry point with argument parsing
├── ssh_honeypot.py       # SSH honeypot implementation
├── web_honeypot.py       # HTTP honeypot implementation
├── ftp_honeypot.py       # FTP honeypot implementation
├── honeypot.log          # Generated log file
├── ftp_honeypot_structured.log  # Structured JSON logs
└── session_*.log         # Individual session logs
```


## ⚠️ Disclaimer

This tool is designed for security research and educational purposes only. Use responsibly and only on networks you own or have permission to monitor. 


--------
