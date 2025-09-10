import os
import socket
import threading
from datetime import datetime, timedelta
import random
import time
import re
from typing import Optional, Tuple, Dict

import paramiko

# User privilege levels
_PRIVILEGE_LEVELS = {
    "guest": 0,      # Limited access
    "user": 1,       # Standard user
    "admin": 2,      # Administrative access
    "root": 3        # Full system access
}

# Default user privileges mapping
_USER_PRIVILEGES = {
    "admin": "admin",
    "root": "root",
    "test": "user",
    "user": "user",
    "guest": "guest"
}


_HOST_KEY_PATH = os.path.join(os.path.dirname(__file__), "ssh_host_key")
_LOG_FILE_PATH = os.path.join(os.path.dirname(__file__), "honeypot.log")
_LOG_LOCK = threading.Lock()
_BOOT_TIME = datetime.utcnow()
_AUTH_EVENTS: list[str] = []

# Global tracking for failed attempts per IP
_FAILED_ATTEMPTS: Dict[str, int] = {}
_LOGIN_SESSIONS: Dict[str, bool] = {}  # Track if IP has successfully logged in

_PERM_DENIED_MESSAGES = [
    "Permission denied",
    "Access denied",
    "You do not have sufficient privileges",
    "Operation not permitted",
    "User not authorized to perform this operation",
]


def _log(message: str, level: str = "INFO", source: str = "SSH") -> None:
    timestamp = datetime.utcnow().isoformat()
    line = f"[{timestamp}Z] [{level}] [{source}] {message}"
    try:
        if level == "WARNING":
            print(f"\033[93m{line}\033[0m")
        elif level == "ALERT":
            print(f"\033[91m{line}\033[0m")
        else:
            print(line)
    except Exception:
        print(line)
    try:
        with _LOG_LOCK:
            with open(_LOG_FILE_PATH, "a", encoding="utf-8") as f:
                f.write(line + "\n")
    except Exception:
        pass


def _ensure_host_key() -> paramiko.RSAKey:
    if os.path.exists(_HOST_KEY_PATH):
        return paramiko.RSAKey(filename=_HOST_KEY_PATH)
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(_HOST_KEY_PATH)
    return key

####### User privilege
def _has_privilege(user_privilege: int, required_privilege: str) -> bool:
    """Check if user has required privilege level"""
    return user_privilege >= _PRIVILEGE_LEVELS.get(required_privilege, 0)


def _get_privilege_name(privilege_level: int) -> str:
    """Convert privilege level to name"""
    for name, level in _PRIVILEGE_LEVELS.items():
        if level == privilege_level:
            return name
    return "guest"

# file access privilege
def _check_file_access(user_privilege: int, file_path: str, operation: str, username: str) -> tuple[bool, str]:
    """
    Check if user has permission to access a file/directory
    Returns (allowed, reason)
    """
    # Normalize path
    if not file_path.startswith("/"):
        file_path = "/" + file_path
    
    # Root user (privilege level 3) can access everything
    if user_privilege >= _PRIVILEGE_LEVELS["root"]:
        return True, "root_access"
    
    # Define access rules based on the house analogy
    access_rules = {
        # Root directory - everyone can read, only root can write
        "/": {
            "read": [0, 1, 2, 3],  # guest, user, admin, root
            "write": [3],  # root only
            "execute": [0, 1, 2, 3]  # everyone
        },
        
        # Root user's home directory - only root
        "/root": {
            "read": [3],  # root only
            "write": [3],  # root only
            "execute": [3]  # root only
        },
        
        # System configuration - admin and root
        "/etc": {
            "read": [2, 3],  # admin, root
            "write": [3],  # root only
            "execute": [2, 3]  # admin, root
        },
        
        # Password files - root only
        "/etc/shadow": {
            "read": [3],  # root only
            "write": [3],  # root only
            "execute": [3]  # root only
        },
        
        # User list - everyone can read
        "/etc/passwd": {
            "read": [0, 1, 2, 3],  # everyone
            "write": [3],  # root only
            "execute": [0, 1, 2, 3]  # everyone
        },
        
        # Network config - admin and root
        "/etc/hosts": {
            "read": [2, 3],  # admin, root
            "write": [3],  # root only
            "execute": [2, 3]  # admin, root
        },
        
        # SSH config - admin and root
        "/etc/ssh": {
            "read": [2, 3],  # admin, root
            "write": [3],  # root only
            "execute": [2, 3]  # admin, root
        },
        
        # Logs - admin and root
        "/var/log": {
            "read": [2, 3],  # admin, root
            "write": [3],  # root only
            "execute": [2, 3]  # admin, root
        },
        
        # Security logs - root only
        "/var/log/auth.log": {
            "read": [3],  # root only
            "write": [3],  # root only
            "execute": [3]  # root only
        },
        
        # User home directories
        "/home": {
            "read": [1, 2, 3],  # user, admin, root
            "write": [3],  # root only
            "execute": [1, 2, 3]  # user, admin, root
        },
        
        # Temporary directory - everyone
        "/tmp": {
            "read": [0, 1, 2, 3],  # everyone
            "write": [0, 1, 2, 3],  # everyone
            "execute": [0, 1, 2, 3]  # everyone
        },
        
        # System binaries - admin and root
        "/bin": {
            "read": [2, 3],  # admin, root
            "write": [3],  # root only
            "execute": [0, 1, 2, 3]  # everyone can execute
        },
        
        # System binaries - admin and root
        "/sbin": {
            "read": [2, 3],  # admin, root
            "write": [3],  # root only
            "execute": [2, 3]  # admin, root
        },
        
        # User binaries - everyone
        "/usr/bin": {
            "read": [0, 1, 2, 3],  # everyone
            "write": [3],  # root only
            "execute": [0, 1, 2, 3]  # everyone
        },
        
        # System binaries - admin and root
        "/usr/sbin": {
            "read": [2, 3],  # admin, root
            "write": [3],  # root only
            "execute": [2, 3]  # admin, root
        },
        
        # Optional software - admin and root
        "/opt": {
            "read": [2, 3],  # admin, root
            "write": [3],  # root only
            "execute": [2, 3]  # admin, root
        }
    }
    
    # Check for specific user home directory access
    if file_path.startswith("/home/"):
        path_parts = file_path.split("/")
        if len(path_parts) >= 3:
            target_user = path_parts[2]
            # Users can access their own home directory
            if target_user == username:
                return True, "own_home"
            # Admin and root can access all user homes
            elif user_privilege >= _PRIVILEGE_LEVELS["admin"]:
                return True, "admin_access"
            else:
                return False, f"access_denied_other_user_home_{target_user}"
    
    # Check for SSH keys and sensitive files
    sensitive_patterns = [
        ("/root/.ssh", "root_ssh_keys"),
        ("/home/*/.ssh", "user_ssh_keys"),
        ("*.pem", "private_key"),
        ("*.key", "private_key"),
        ("*credentials*", "credentials_file"),
        ("*password*", "password_file"),
        ("*secret*", "secret_file")
    ]
    
    for pattern, reason in sensitive_patterns:
        if pattern.startswith("/root/.ssh") and file_path.startswith("/root/.ssh"):
            if user_privilege < _PRIVILEGE_LEVELS["root"]:
                return False, reason
        elif pattern.startswith("/home/*/.ssh") and "/.ssh" in file_path:
            if user_privilege < _PRIVILEGE_LEVELS["admin"]:
                return False, reason
        elif pattern.endswith("*") and pattern[1:-1] in file_path.lower():
            if user_privilege < _PRIVILEGE_LEVELS["admin"]:
                return False, reason
    
    # Check exact path matches first
    if file_path in access_rules:
        rule = access_rules[file_path]
        if operation in rule and user_privilege in rule[operation]:
            return True, f"allowed_{operation}"
        else:
            return False, f"denied_{operation}_privilege_{user_privilege}"
    
    # Check parent directory rules
    for rule_path, rule in access_rules.items():
        if file_path.startswith(rule_path + "/") or file_path == rule_path:
            if operation in rule and user_privilege in rule[operation]:
                return True, f"allowed_{operation}_parent"
            else:
                return False, f"denied_{operation}_parent_privilege_{user_privilege}"
    
    # Default: deny access to unknown paths for non-admin users
    if user_privilege < _PRIVILEGE_LEVELS["admin"]:
        return False, "unknown_path_denied"
    
    return True, "admin_default_allow"


def _log_file_access(user: str, operation: str, path: str, allowed: bool, reason: str, privilege: int):
    """Log file access attempts for security monitoring"""
    status = "ALLOWED" if allowed else "DENIED"
    privilege_name = _get_privilege_name(privilege)
    _log(f"FILE_ACCESS: {user} ({privilege_name}) {operation} {path} - {status} ({reason})", 
         level="INFO" if allowed else "WARNING")


def _read_password_input(chan, prompt: str) -> str:
    """Read password input from channel with hidden input"""
    try:
        chan.send(prompt.encode())
        chan.send(b"\x1b[8m")  # Hide input
        password_data = b""
        while True:
            data = chan.recv(1)
            if data == b"\r" or data == b"\n":
                break
            elif data == b"\x7f" or data == b"\b":  # Backspace
                if password_data:
                    password_data = password_data[:-1]
                    chan.send(b"\b \b")
            else:
                password_data += data
                chan.send(b"*")
        chan.send(b"\x1b[0m\r\n")  # Show input again
        return password_data.decode('utf-8', errors='ignore')
    except Exception as e:
        _log(f"PASSWORD_INPUT_ERROR: {str(e)}")
        return ""


def _check_sudo_password(user: str, password: str) -> bool:
    """Check if password matches default credentials for sudo"""
    # Default passwords for admin and root
    default_passwords = {
        "admin": "admin",
        "root": "root"
    }
    
    # Check if user has default password
    if user in default_passwords:
        return password == default_passwords[user]
    
    # For other users, always fail
    return False

 #######

class _SSHServer(paramiko.ServerInterface):
    def __init__(self, accept_username: Optional[str], accept_password: Optional[str], peername: str):
        super().__init__()
        self.accept_username = accept_username
        self.accept_password = accept_password
        self.event = threading.Event()
        self.peername = peername
        self.authenticated_user: Optional[str] = None
        # ##User privilege
        self.user_privilege: int = _PRIVILEGE_LEVELS["guest"]  # Default privilege
        ######

    def check_auth_password(self, username: str, password: str) -> int:
        msg = f"SSH auth from {self.peername} username='{username}' password='***'"
        _log(msg)
        try:
            _AUTH_EVENTS.append(msg)
        except Exception:
            pass

        # Track failed attempts per IP
        if self.peername not in _FAILED_ATTEMPTS:
            _FAILED_ATTEMPTS[self.peername] = 0
        
        # Check if this IP has already successfully logged in
        if self.peername in _LOGIN_SESSIONS and _LOGIN_SESSIONS[self.peername]:
            # Force them to login again after 10 seconds
            _log(f"SSH redirecting {self.peername} to login screen")
            return paramiko.AUTH_FAILED

        # Check if credentials are correct
        credentials_correct = True
        if self.accept_username is not None and username != self.accept_username:
            credentials_correct = False
        if self.accept_password is not None and password != self.accept_password:
            credentials_correct = False

        # In default mode (no specific credentials), check against passwords.txt file
        if self.accept_username is None and self.accept_password is None:
            # First check for anonymous access (any username with password "anonymous" except admin/root)
            if password == "anonymous" and username.lower() not in ["admin", "root"]:
                credentials_correct = True
            else:
                # Load credentials from passwords.txt file
                correct_credentials = []
                try:
                    with open("passwords.txt", "r") as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith("#") and ":" in line:
                                user, pwd = line.split(":", 1)
                                correct_credentials.append((user.strip(), pwd.strip()))
                except FileNotFoundError:
                    # Fallback to default credentials if file not found
                    correct_credentials = [
                        ("admin", "admin"),
                        ("root", "root"),
                        ("test", "test"),
                        ("user", "user"),
                        ("anonymous", "anonymous")  # Add anonymous as fallback
                    ]
                
                # Check if current credentials match any of the "correct" ones
                credentials_correct = (username, password) in correct_credentials

        if credentials_correct:
            # Correct credentials - accept immediately
            self.authenticated_user = username
            
            # Set user privilege based on username
            # Special handling for anonymous access (excluding admin/root)
            if password == "anonymous" and username.lower() not in ["admin", "root"]:
                # Anonymous users get guest privileges by default
                self.user_privilege = _PRIVILEGE_LEVELS["guest"]
            else:
                self.user_privilege = _PRIVILEGE_LEVELS.get(
                    _USER_PRIVILEGES.get(username, "guest"), 
                    _PRIVILEGE_LEVELS["guest"]
                )
            #########

            _LOGIN_SESSIONS[self.peername] = True
            # User privilege
            if password == "anonymous" and username.lower() not in ["admin", "root"]:
                _log(f"SSH auth SUCCESS for {self.peername} with ANONYMOUS access (username: {username}, privilege: {_get_privilege_name(self.user_privilege)})")
            else:
                _log(f"SSH auth SUCCESS for {self.peername} with correct credentials (privilege: {_get_privilege_name(self.user_privilege)})")
            #########

            return paramiko.AUTH_SUCCESSFUL
        else:
            # Wrong credentials - track failed attempts
            _FAILED_ATTEMPTS[self.peername] += 1
            
            
            # Check if they've made enough failed attempts (more than 3, since SSH clients typically try 3 times)
            required_attempts = 3
            _log(f"SSH auth attempt {_FAILED_ATTEMPTS[self.peername]} for {self.peername} with wrong credentials")
            
            if _FAILED_ATTEMPTS[self.peername] > required_attempts:
                # They've made enough failed attempts, accept the login anyway
                self.authenticated_user = username
                
                # Set user privilege based on username (default to guest for failed attempts)
                # Special handling for anonymous access (excluding admin/root)
                if password == "anonymous" and username.lower() not in ["admin", "root"]:
                    # Anonymous users get guest privileges by default
                    self.user_privilege = _PRIVILEGE_LEVELS["guest"]
                else:
                    self.user_privilege = _PRIVILEGE_LEVELS.get(
                        _USER_PRIVILEGES.get(username, "guest"), 
                        _PRIVILEGE_LEVELS["guest"]
                    )
                
                _LOGIN_SESSIONS[self.peername] = True
            # User privilege
                if password == "anonymous" and username.lower() not in ["admin", "root"]:
                    _log(f"SSH auth SUCCESS for {self.peername} with ANONYMOUS access after {_FAILED_ATTEMPTS[self.peername]} failed attempts (username: {username}, privilege: {_get_privilege_name(self.user_privilege)})")
                else:
                    _log(f"SSH auth SUCCESS for {self.peername} after {_FAILED_ATTEMPTS[self.peername]} failed attempts (privilege: {_get_privilege_name(self.user_privilege)})")
                ######

                return paramiko.AUTH_SUCCESSFUL
            else:
                # Still need more failed attempts
                _log(f"SSH auth FAILED for {self.peername} (attempt {_FAILED_ATTEMPTS[self.peername]}/{required_attempts}) - need {required_attempts - _FAILED_ATTEMPTS[self.peername] + 1} more attempts")
                return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username: str) -> str:
        return "password"

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel) -> bool:
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes) -> bool:
        return True


def _fake_command_response(cmd: str, user: str) -> str:
    if cmd in {"whoami"}:
        return user
    if cmd.startswith("echo "):
        return cmd[5:].lstrip()
    if cmd in {"uname", "uname -a"}:
        return "Linux 5.15.0-1021-azure #25-Ubuntu SMP x86_64 GNU/Linux"
    if cmd in {"id"}:
        return f"uid=1000({user}) gid=1000({user}) groups=1000({user})"
    if cmd in {"ls", "dir"}:
        return "bin  boot  etc  home  lib  tmp  var"
    if cmd.startswith("cat "):
        return "Permission denied"
    return f"bash: {cmd}: command not found"


def _handle_client(client: socket.socket, addr: Tuple[str, int], host_key: paramiko.PKey,
                   accept_username: Optional[str], accept_password: Optional[str]) -> None:
    peer = f"{addr[0]}:{addr[1]}"
    try:
        transport = paramiko.Transport(client)
        transport.add_server_key(host_key)
        server = _SSHServer(accept_username, accept_password, peer)
        transport.start_server(server=server)

        chan = transport.accept(timeout=20)
        if chan is None:
            _log(f"SSH no channel from {peer}")
            return
        server.event.wait(20)

        user_display = server.authenticated_user or "unknown"
        host_display = "honeypot"
        attacker_ip = addr[0]
        
        # Session is persistent until user explicitly quits
        
        banner = (
            f"Welcome {user_display}!\r\n"
            f"Type 'info' for available commands. Type 'exit' to close.\r\n"
        )
        chan.send(banner)

        # --- Simple in-memory filesystem and shell state ---
        fs = {
            "": {  # root
                "type": "dir",
                "children": {
                    "bin": {"type": "dir", "children": {
                        "[": {"type": "file", "content": ""},
                        "1password2john": {"type": "file", "content": ""},
                        "2to3-2.7": {"type": "file", "content": ""},
                        "7z": {"type": "file", "content": ""},
                        "7z2john": {"type": "file", "content": ""},
                        "7za": {"type": "file", "content": ""},
                        "7zr": {"type": "file", "content": ""},
                        "aa-enabled": {"type": "file", "content": ""},
                        "aa-exec": {"type": "file", "content": ""},
                        "aa-features-abi": {"type": "file", "content": ""},
                        "ab": {"type": "file", "content": ""},
                        "addr2line": {"type": "file", "content": ""},
                        "aircrack-ng": {"type": "file", "content": ""},
                        "airdecap-ng": {"type": "file", "content": ""},
                        "airdecloak-ng": {"type": "file", "content": ""},
                        "airolib-ng": {"type": "file", "content": ""},
                        "amass": {"type": "file", "content": ""},
                        "animate": {"type": "file", "content": ""},
                        "ansible2john": {"type": "file", "content": ""},
                        "apt": {"type": "file", "content": ""},
                        "apt-cache": {"type": "file", "content": ""},
                        "awk": {"type": "file", "content": ""},
                        "base64": {"type": "file", "content": ""},
                        "bash": {"type": "file", "content": ""},
                        "cat": {"type": "file", "content": ""},
                        "cd": {"type": "file", "content": ""},
                        "chmod": {"type": "file", "content": ""},
                        "chown": {"type": "file", "content": ""},
                        "cp": {"type": "file", "content": ""},
                        "curl": {"type": "file", "content": ""},
                        "cut": {"type": "file", "content": ""},
                        "date": {"type": "file", "content": ""},
                        "dd": {"type": "file", "content": ""},
                        "df": {"type": "file", "content": ""},
                        "dig": {"type": "file", "content": ""},
                        "dmesg": {"type": "file", "content": ""},
                        "echo": {"type": "file", "content": ""},
                        "egrep": {"type": "file", "content": ""},
                        "env": {"type": "file", "content": ""},
                        "gcc": {"type": "file", "content": ""},
                        "grep": {"type": "file", "content": ""},
                        "head": {"type": "file", "content": ""},
                        "host": {"type": "file", "content": ""},
                        "hostname": {"type": "file", "content": ""},
                        "htop": {"type": "file", "content": ""},
                        "ifconfig": {"type": "file", "content": ""},
                        "ip": {"type": "file", "content": ""},
                        "jq": {"type": "file", "content": ""},
                        "john": {"type": "file", "content": ""},
                        "kill": {"type": "file", "content": ""},
                        "killall": {"type": "file", "content": ""},
                        "ln": {"type": "file", "content": ""},
                        "less": {"type": "file", "content": ""},
                        "ls": {"type": "file", "content": ""},
                        "lsmod": {"type": "file", "content": ""},
                        "lsof": {"type": "file", "content": ""},
                        "md5sum": {"type": "file", "content": ""},
                        "mkdir": {"type": "file", "content": ""},
                        "mount": {"type": "file", "content": ""},
                        "mv": {"type": "file", "content": ""},
                        "nano": {"type": "file", "content": ""},
                        "nc": {"type": "file", "content": ""},
                        "netcat": {"type": "file", "content": ""},
                        "netstat": {"type": "file", "content": ""},
                        "nmap": {"type": "file", "content": ""},
                        "nslookup": {"type": "file", "content": ""},
                        "openssl": {"type": "file", "content": ""},
                        "passwd": {"type": "file", "content": ""},
                        "ping": {"type": "file", "content": ""},
                        "ps": {"type": "file", "content": ""},
                        "python3": {"type": "file", "content": ""},
                        "realpath": {"type": "file", "content": ""},
                        "rm": {"type": "file", "content": ""},
                        "rmdir": {"type": "file", "content": ""},
                        "rsync": {"type": "file", "content": ""},
                        "scp": {"type": "file", "content": ""},
                        "sed": {"type": "file", "content": ""},
                        "sh": {"type": "file", "content": ""},
                        "sleep": {"type": "file", "content": ""},
                        "ssh": {"type": "file", "content": ""},
                        "stat": {"type": "file", "content": ""},
                        "strings": {"type": "file", "content": ""},
                        "su": {"type": "file", "content": ""},
                        "sudo": {"type": "file", "content": ""},
                        "systemctl": {"type": "file", "content": ""},
                        "tail": {"type": "file", "content": ""},
                        "tar": {"type": "file", "content": ""},
                        "tee": {"type": "file", "content": ""},
                        "telnet": {"type": "file", "content": ""},
                        "top": {"type": "file", "content": ""},
                        "touch": {"type": "file", "content": ""},
                        "tr": {"type": "file", "content": ""},
                        "uname": {"type": "file", "content": ""},
                        "unzip": {"type": "file", "content": ""},
                        "uptime": {"type": "file", "content": ""},
                        "vi": {"type": "file", "content": ""},
                        "vim": {"type": "file", "content": ""},
                        "wc": {"type": "file", "content": ""},
                        "wget": {"type": "file", "content": ""},
                        "which": {"type": "file", "content": ""},
                        "xxd": {"type": "file", "content": ""},
                        "xz": {"type": "file", "content": ""}
                    }},
                    "boot": {"type": "dir", "children": {
                        "config-6.12.25-amd64": {"type": "file", "content": "CONFIG_...=y"},
                        "grub": {"type": "dir", "children": {}},
                        "initrd.img-6.12.25-amd64": {"type": "file", "content": "INITRD"},
                        "System.map-6.12.25-amd64": {"type": "file", "content": "SYMBOLS..."},
                        "vmlinuz-6.12.25-amd64": {"type": "file", "content": "LINUXKERNEL"}
                    }},
                    "etc": {"type": "dir", "children": {
                        "hosts": {"type": "file", "content": "127.0.0.1 localhost\n192.168.1.1 router"},
                        "hostname": {"type": "file", "content": "srv-01"},
                        "passwd": {"type": "file", "content": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\njohn:x:1000:1000:John Doe,,,:/home/john:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nmysql:x:999:999:MySQL Server,,,:/var/lib/mysql:/bin/false"},
                        "shadow": {"type": "file", "content": "root:*:19579:0:99999:7:::\ndaemon:*:19579:0:99999:7:::\njohn:$y$j9T$F4B6U1Q7s9q8d2p1E1bV1.$0JjV9Q2r8q7w6t5Y4u3I2e1R0T9Y2U3I4O5P6Q7W:19579:0:99999:7:::\nwww-data:*:19579:0:99999:7:::\nmysql:!:19579:0:99999:7:::"},
                        "ssh": {"type": "dir", "children": {"sshd_config": {"type": "file", "content": "Port 22\nPermitRootLogin no"}}},
                        "resolv.conf": {"type": "file", "content": "nameserver 8.8.8.8"},
                    }},
                    "home": {"type": "dir", "children": {
                        "john": {"type": "dir", "children": {
                            ".bash_history": {"type": "file", "content": "ls -la\ncat /etc/passwd\nssh root@10.0.0.5"},
                            "user.txt": {"type": "file", "content": "Welcome to the system, John."},
                            ".ssh": {"type": "dir", "children": {"id_rsa": {"type": "file", "content": "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAA.....BASE64...DATA...\n-----END OPENSSH PRIVATE KEY-----"}}}
                        }},
                        "www-data": {"type": "dir", "children": {"web_app.zip": {"type": "file", "content": "PK\x03\x04ZIPDATA"}}},
                        user_display: {"type": "dir", "children": {}}
                    }},
                    "lib": {"type": "dir", "children": {
                        "x86_64-linux-gnu": {"type": "dir", "children": {}},
                        "systemd": {"type": "dir", "children": {}},
                        "apache2": {"type": "dir", "children": {}},
                        "openssl": {"type": "dir", "children": {}},
                        "python3": {"type": "dir", "children": {}},
                        "llvm-18": {"type": "dir", "children": {}},
                        "llvm-19": {"type": "dir", "children": {}},
                        "NetworkManager": {"type": "dir", "children": {}},
                        "qt5": {"type": "dir", "children": {}},
                        "qt6": {"type": "dir", "children": {}},
                        "openssl": {"type": "dir", "children": {}},
                        "libopenvas_misc.so": {"type": "file", "content": "ELF..."},
                        "libopenvas_nasl.so": {"type": "file", "content": "ELF..."},
                        "libettercap.so": {"type": "file", "content": "ELF..."},
                        "libettercap-ui.so": {"type": "file", "content": "ELF..."},
                        "libarmadillo.so.14": {"type": "file", "content": "ELF..."},
                        "libzopfli.so.1.0.3": {"type": "file", "content": "ELF..."},
                        "libzopflipng.so.1.0.3": {"type": "file", "content": "ELF..."}
                    }},
                    "proc": {"type": "dir", "children": {
                        "cpuinfo": {"type": "file", "content": "processor\t: 0\nmodel name\t: Intel(R) Xeon(R) CPU"},
                        "meminfo": {"type": "file", "content": "MemTotal:       2048000 kB"},
                        "uptime": {"type": "file", "content": "12345.67 54321.00"},
                        "stat": {"type": "file", "content": "cpu  2255 34 2290 22625563 6290 127 456"},
                        "version": {"type": "file", "content": "Linux version 5.15.0 (gcc version 11.4.0)"},
                        "vmstat": {"type": "file", "content": "nr_free_pages 1024"},
                        "mounts": {"type": "file", "content": "/dev/sda1 / ext4 rw,relatime 0 0"},
                        "modules": {"type": "file", "content": "xt_conntrack 16384 1\nbr_netfilter 28672 0"},
                        "softirqs": {"type": "file", "content": "CPU0: 0 1 2 3 4"},
                        "self": {"type": "dir", "children": {}},
                        "1": {"type": "dir", "children": {}},
                        "20": {"type": "dir", "children": {}},
                        "1204": {"type": "dir", "children": {}},
                        "1244": {"type": "dir", "children": {}},
                        "1374": {"type": "dir", "children": {}},
                        "1419": {"type": "dir", "children": {}},
                        "1472": {"type": "dir", "children": {}},
                        "1528": {"type": "dir", "children": {}},
                        "1584": {"type": "dir", "children": {}},
                        "1716": {"type": "dir", "children": {}},
                        "1821": {"type": "dir", "children": {}},
                        "254": {"type": "dir", "children": {}},
                        "270": {"type": "dir", "children": {}},
                        "545": {"type": "dir", "children": {}},
                        "702": {"type": "dir", "children": {}},
                        "833": {"type": "dir", "children": {}},
                        "982": {"type": "dir", "children": {}},
                        "199402": {"type": "dir", "children": {}},
                        "200516": {"type": "dir", "children": {}},
                        "92164": {"type": "dir", "children": {}},
                        "zoneinfo": {"type": "file", "content": "Node 0, zone   DMA"}
                    }},
                    "tmp": {"type": "dir", "children": {}},
                    "var": {"type": "dir", "children": {"log": {"type": "dir", "children": {"auth.log": {"type": "file", "content": ""}, "apache2": {"type": "dir", "children": {"access.log": {"type": "file", "content": "127.0.0.1 - - [01/Jan/2025:00:00:00 +0000] \"GET / HTTP/1.1\" 200 123"}}}, "syslog": {"type": "file", "content": ""}, "attacker_ip": {"type": "file", "content": f"{attacker_ip} {datetime.utcnow().isoformat()}Z"}}}, "www": {"type": "dir", "children": {"html": {"type": "dir", "children": {"index.html": {"type": "file", "content": "<html><body><h1>It works!</h1></body></html>"}}}}}}},
                    "opt": {"type": "dir", "children": {
                        "microsoft": {"type": "dir", "children": {}},
                        "splunk": {"type": "dir", "children": {}},
                        "splunkforwarder": {"type": "dir", "children": {}},
                        "scripts": {"type": "dir", "children": {"backup.sh": {"type": "file", "content": "#!/bin/bash\necho Backing up /var/www...\n# TODO: implement"}}}
                    }},
                    "root": {"type": "dir", "children": {".bash_history": {"type": "file", "content": "sudo su\nwhoami"}, "file.txt": {"type": "file", "content": "DYNAMIC_FLAG"}, ".ssh": {"type": "dir", "children": {"authorized_keys": {"type": "file", "content": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD... user@host"}}}}},
                },
            }
        }
        cwd = [""]  # path components starting from root node key ""

        def _path_str() -> str:
            if cwd == [""]:
                return "/"
            return "/" + "/".join(cwd[1:])

        def _resolve(path: str):
            # file access privilege
            # Check file access permissions using the comprehensive access control system
            allowed, reason = _check_file_access(server.user_privilege, path, "read", user_display)
            _log_file_access(user_display, "read", path, allowed, reason, server.user_privilege)
            
            if not allowed:
                return None, None, None
            #######

            # returns (node, parent_node, name)
            parts = []
            if path.startswith("/"):
                node = fs[""]
                parts = [p for p in path.split("/") if p]
            else:
                node = fs[""]
                # navigate to cwd first
                cur = fs[""]
                for p in cwd[1:]:
                    cur = cur["children"].get(p)
                    if cur is None or cur.get("type") != "dir":
                        return None, None, None
                node = cur
                parts = [p for p in path.split("/") if p]

            parent = None
            name = None
            cur = node
            for idx, p in enumerate(parts):
                parent = cur
                name = p
                cur = cur.get("children", {}).get(p)
                if cur is None:
                    # not found
                    if idx == len(parts) - 1:
                        return None, parent, name
                    return None, None, None
            return cur, parent, name

        def _prompt() -> bytes:
            # User privilege
            # user@host:/path$ with privilege indicator
            privilege_char = "#" if _has_privilege(server.user_privilege, "admin") else "$"
            return f"{user_display}@{host_display}:{_path_str()}{privilege_char} ".encode()
            ##########

        # helper to get current directory node
        def _cwd_node():
            cur = fs[""]
            for p in cwd[1:]:
                cur = cur["children"].get(p)
                if cur is None:
                    break
            return cur

        chan.send(_prompt())
        line_buf: list[str] = []
        history: list[str] = []
        env_vars: dict[str, str] = {
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "USER": user_display,
            "HOME": f"/home/{user_display}",
            "SHELL": "/bin/bash",
            "HOSTNAME": "srv-01",
            "REMOTE_ADDR": attacker_ip,
            "LANG": "en_US.UTF-8",
            "PWD": "/",
            "TERM": "xterm-256color",
            "LS_COLORS": "rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.zip=01;31",
        }
        aliases: dict[str, str] = {}
        session_state = {
            "crontab": [],
            "authorized_keys": [],
            "etc_hosts": "127.0.0.1 localhost\n192.168.1.1 router\n",
        }

        # Command set for autocompletion
        command_set = {
            "pwd", "cd", "ls", "cat", "touch", "mkdir", "rm", "rmdir", "echo",
            "whoami", "id", "uname", "hostname", "ifconfig", "ip", "netstat", "ps",
            "history", "clear", "date", "uptime", "env", "export", "alias", "which",
            "head", "tail", "mv", "cp", "grep", "find", "who", "w", "myip",
            "exit", "info", "sudo", "su"
        }

        def _complete_path(prefix: str) -> list[str]:
            # Determine base directory and partial name
            if prefix.startswith("/"):
                base_parts = [p for p in prefix.split("/") if p]
                partial = ""
                if prefix.endswith("/"):
                    dir_parts = base_parts
                else:
                    dir_parts = base_parts[:-1]
                    partial = base_parts[-1] if base_parts else ""
                node = fs[""]
                for p in dir_parts:
                    node = node.get("children", {}).get(p)
                    if not node or node.get("type") != "dir":
                        return []
                candidates = []
                for name in node.get("children", {}).keys():
                    if name.startswith(partial):
                        full = "/" + "/".join(dir_parts + [name]) if dir_parts else "/" + name
                        # append slash for directories
                        child = node["children"][name]
                        if child.get("type") == "dir":
                            full += "/"
                        candidates.append(full)
                return sorted(candidates)
            else:
                # relative to cwd
                cur = _cwd_node()
                if not cur or cur.get("type") != "dir":
                    return []
                parts = [p for p in prefix.split("/") if p]
                partial = ""
                node = cur
                if prefix.endswith("/"):
                    walk_parts = parts
                else:
                    walk_parts = parts[:-1]
                    partial = parts[-1] if parts else ""
                # walk subdirs
                for p in walk_parts:
                    node = node.get("children", {}).get(p)
                    if not node or node.get("type") != "dir":
                        return []
                candidates = []
                for name in node.get("children", {}).keys():
                    if name.startswith(partial):
                        suffix = name
                        child = node["children"][name]
                        if child.get("type") == "dir":
                            suffix += "/"
                        base = "/".join(parts[:-1]) if parts and not prefix.endswith("/") else "/".join(parts)
                        completion = (base + ("/" if base else "") + suffix) if base else suffix
                        candidates.append(completion)
                return sorted(candidates)
        hist_idx: Optional[int] = None
        saved_current: str = ""
        while True:
            data = chan.recv(1)
            if not data:
                break

            ch = data[0]
            # Handle CR or LF as Enter
            if ch in (10, 13):
                line = "".join(line_buf).strip()
                line_buf.clear()
                chan.send(b"\r\n")

                if not line:
                    chan.send(_prompt())
                    continue

                _log(f"{peer} ran: {line}")
                # reset history nav state on submit
                hist_idx = None
                saved_current = ""
                # simulate small random IO latency
                try:
                    time.sleep(random.uniform(0.05, 0.25))
                except Exception:
                    pass

                # expand simple aliases
                parts = line.split()
                if parts and parts[0] in aliases:
                    expanded = (aliases[parts[0]] + " " + " ".join(parts[1:])).strip()
                    parts = expanded.split()
                cmd = parts[0]
                args = parts[1:]

                if cmd in {"exit", "logout", "quit"}:
                    # Clean up session on explicit exit
                    if peer in _LOGIN_SESSIONS:
                        _LOGIN_SESSIONS[peer] = False
                    _log(f"SSH session ended by user {user_display} from {peer}")
                    chan.send(b"Bye!\r\n")
                    break
                elif cmd == "info":
                    help_map = {
                        "pwd": "Print current working directory",
                        "cd": "Change directory: cd [path|..|~]",
                        "ls": "List directory contents (supports -a, -l)",
                        "cat": "Show file contents: cat <file> [file2 ...]",
                        "touch": "Create empty file: touch <file>",
                        "mkdir": "Create directory: mkdir <dir>",
                        "rm": "Remove file: rm <path>",
                        "rmdir": "Remove empty directory: rmdir <dir>",
                        "echo": "Print text or redirect: echo <text> [> file]",
                        "whoami": "Show current user",
                        "id": "Show user/group ids",
                        "uname": "Show system name (use -a for details)",
                        "hostname": "Print system hostname",
                        "who": "Show who is logged in",
                        "w": "Show who is logged in and their source IP",
                        "myip": "Print your remote IP as seen by the server",
                        "ifconfig": "Show network interfaces",
                        "ip": "Alias of ifconfig",
                        "netstat": "Show network connections",
                        "ps": "List running processes",
                        "history": "Show command history",
                        "grep": "Search for patterns in files: grep <pattern> <file>",
                        "find": "Search for files in a directory hierarchy",
                        "head": "Output the first part of files",
                        "tail": "Output the last part of files",
                        "mv": "Move or rename files: mv <src> <dst>",
                        "cp": "Copy files: cp <src> <dst>",
                        "chmod": "Change file modes or Access Control Lists",
                        "chown": "Change file owner and group",
                        "df": "Report file system disk space usage",
                        "du": "Estimate file space usage",
                        "top": "Display Linux tasks",
                        "service": "Run a System V init script",
                        "systemctl": "Control the systemd system and service manager",
                        "curl": "Transfer data from or to a server",
                        "wget": "The non-interactive network downloader",
                        "ping": "Send ICMP ECHO_REQUEST to network hosts",
                        "uptime": "Show how long the system has been running",
                        "date": "Print or set the system date and time",
                        "which": "Locate a command",
                        "env": "Show or set environment variables",
                        "export": "Set environment variables",
                        "alias": "Define or display aliases",
                        "clear": "Clear the terminal screen",
                        "exit": "Close the session",
                        "info": "Show this info or: info <command>",
                        "sudo": "Execute command as another user (requires password)",
                        "su": "Switch to another user (requires password)",
                        # file access privilege
                        # "privileges": "Show current user privileges and access guide",
                        # "fileaccess": "Check file access permissions: fileaccess <path>",
                    }
                    if args:
                        topic = args[0]
                        desc = help_map.get(topic)
                        if desc:
                            chan.send((f"{topic}: {desc}\r\n").encode())
                        else:
                            chan.send((f"No help available for '{topic}'\r\n").encode())
                    else:
                        lines = [
                            "For more information on a specific command, type: info <command>",
                            "",
                        ]
                        width = max(len(k) for k in help_map.keys())
                        for k in sorted(help_map.keys()):
                            lines.append(f"{k.ljust(width)}  {help_map[k]}")
                        chan.send(("\r\n".join(lines) + "\r\n").encode())
                elif cmd == "pwd":
                    chan.send((_path_str() + "\r\n").encode())
                elif cmd == "whoami":
                   # User privilege
                    privilege_name = _get_privilege_name(server.user_privilege)
                    chan.send((f"{user_display} ({privilege_name})\r\n").encode())
                    ##########
                elif cmd == "id":
                # User privilege
                    privilege_name = _get_privilege_name(server.user_privilege)
                    groups = "1000(user)" if server.user_privilege < _PRIVILEGE_LEVELS["admin"] else "0(root),1000(user)"
                    chan.send((f"uid=1000({user_display}) gid=1000({user_display}) groups={groups}\r\n").encode())
                    #########
                elif cmd == "history":
                    out = "\r\n".join(f"  {i+1}  {h}" for i, h in enumerate(history)) + "\r\n"
                    chan.send(out.encode())
                elif cmd == "uname":
                    if args and args[0] == "-a":
                        chan.send(b"Linux honeypot 5.15.0-1021-azure #25-Ubuntu SMP x86_64 GNU/Linux\r\n")
                    else:
                        chan.send(b"Linux\r\n")
                elif cmd == "hostname":
                    chan.send(b"srv-01\r\n")
                elif cmd in {"who", "w"}:
                    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M")
                    chan.send((f"{user_display} pts/0        {now}    {attacker_ip}\r\n").encode())
                elif cmd == "myip":
                    chan.send((attacker_ip + "\r\n").encode())
                elif cmd == "sudo":
                    if not args:
                        chan.send(b"usage: sudo -h | -K | -k | -V\r\nusage: sudo -v [-AknS] [-g group] [-h host] [-p prompt] [-u user]\r\nusage: sudo -l [-AknS] [-g group] [-h host] [-p prompt] [-u user]\r\nusage: sudo [-AbEHknPS] [-r role] [-t type] [-C num] [-g group] [-h host] [-p prompt] [-u user] [VAR=value] [-i|-s] [<command>]\r\nusage: sudo -e [-AknS] [-r role] [-t type] [-C num] [-g group] [-h host] [-p prompt] [-u user] file ...\r\n")
                    elif args[0] == "-l":
                        # List sudo privileges - any user can check
                        _log(f"SUDO_LIST: {user_display} ({_get_privilege_name(server.user_privilege)}) checked sudo privileges")
                        chan.send(b"Matching Defaults entries for " + user_display.encode() + b" on " + host_display.encode() + b":\r\n")
                        chan.send(b"    env_reset, mail_badpass, secure_path=/usr/local/sbin\\:/usr/local/bin\\:/usr/sbin\\:/usr/bin\\:/sbin\\:/bin\\:/snap/bin\r\n\r\n")
                        chan.send(b"User " + user_display.encode() + b" may run the following commands on " + host_display.encode() + b":\r\n")
                        chan.send(b"    (ALL : ALL) ALL\r\n")
                    elif args[0] == "-k":
                        # Kill timestamp - no password needed
                        _log(f"SUDO_KILL: {user_display} ({_get_privilege_name(server.user_privilege)}) killed sudo timestamp")
                        chan.send(b"sudo: timestamp removed\r\n")
                    elif args[0] == "su" and len(args) > 1:
                        # sudo su <user> - special handling
                        target_user = args[1]
                        _log(f"SUDO_SU_USER: {user_display} ({_get_privilege_name(server.user_privilege)}) attempted sudo su {target_user}")
                        
                        # Only ask for password when switching to admin or root
                        if target_user in ["admin", "root"]:
                            password = _read_password_input(chan, f"[sudo] password for {target_user}: ")
                            _log(f"SUDO_PASSWORD_INPUT: {user_display} entered password for sudo su {target_user}: {password}")
                            
                            if _check_sudo_password(target_user, password):
                                # Password correct - switch to user
                                _log(f"SUDO_SUCCESS: {user_display} successfully switched to {target_user}")
                                chan.send(f"Switched to user {target_user}\r\n".encode())
                                # Update the user display and privilege
                                user_display = target_user
                                server.user_privilege = _PRIVILEGE_LEVELS.get(_USER_PRIVILEGES.get(target_user, "guest"), _PRIVILEGE_LEVELS["guest"])
                            else:
                                chan.send(b"Sorry, try again.\r\n")
                                password2 = _read_password_input(chan, f"[sudo] password for {target_user}: ")
                                _log(f"SUDO_PASSWORD_INPUT_2: {user_display} entered second password for sudo su {target_user}: {password2}")
                                
                                if _check_sudo_password(target_user, password2):
                                    _log(f"SUDO_SUCCESS: {user_display} successfully switched to {target_user} on second attempt")
                                    chan.send(f"Switched to user {target_user}\r\n".encode())
                                    user_display = target_user
                                    server.user_privilege = _PRIVILEGE_LEVELS.get(_USER_PRIVILEGES.get(target_user, "guest"), _PRIVILEGE_LEVELS["guest"])
                                else:
                                    chan.send(b"sudo: 2 incorrect password attempts\r\n")
                        else:
                            # For other users, switch directly without password
                            _log(f"SUDO_SU_DIRECT: {user_display} switched to {target_user} without password")
                            chan.send(f"Switched to user {target_user}\r\n".encode())
                            user_display = target_user
                            server.user_privilege = _PRIVILEGE_LEVELS.get(_USER_PRIVILEGES.get(target_user, "guest"), _PRIVILEGE_LEVELS["guest"])
                    else:
                        # All other sudo commands - any user can run, check password
                        _log(f"SUDO_ATTEMPT: {user_display} ({_get_privilege_name(server.user_privilege)}) attempted: sudo {' '.join(args)}")
                        
                        # First password attempt
                        password1 = _read_password_input(chan, f"[sudo] password for {user_display}: ")
                        _log(f"SUDO_PASSWORD_INPUT: {user_display} entered password for sudo {' '.join(args)}: {password1}")
                        
                        if _check_sudo_password(user_display, password1):
                            # Password correct - execute command
                            _log(f"SUDO_SUCCESS: {user_display} successfully executed sudo {' '.join(args)}")
                            chan.send(f"Command executed successfully\r\n".encode())
                        else:
                            chan.send(b"Sorry, try again.\r\n")
                            
                            # Second password attempt
                            password2 = _read_password_input(chan, f"[sudo] password for {user_display}: ")
                            _log(f"SUDO_PASSWORD_INPUT_2: {user_display} entered second password for sudo {' '.join(args)}: {password2}")
                            
                            if _check_sudo_password(user_display, password2):
                                _log(f"SUDO_SUCCESS: {user_display} successfully executed sudo {' '.join(args)} on second attempt")
                                chan.send(f"Command executed successfully\r\n".encode())
                            else:
                                chan.send(b"sudo: 2 incorrect password attempts\r\n")
                elif cmd == "su":
                    target_user = args[0] if args else "root"
                    
                    # Log su attempt
                    _log(f"SU_ATTEMPT: {user_display} ({_get_privilege_name(server.user_privilege)}) attempted to switch to: {target_user}")
                    
                    # Check if user can switch to target user
                    if target_user == "root":
                        if server.user_privilege >= _PRIVILEGE_LEVELS["admin"]:
                            # Read password input
                            password = _read_password_input(chan, "Password: ")
                            _log(f"SU_PASSWORD_INPUT: {user_display} entered password for su {target_user}: {password}")
                            chan.send(b"su: Authentication failure\r\n")
                        else:
                            chan.send(b"su: must be run from a terminal\r\n")
                    elif target_user in ["admin", "user", "test"]:
                        if server.user_privilege >= _PRIVILEGE_LEVELS["user"]:
                            # Read password input
                            password = _read_password_input(chan, "Password: ")
                            _log(f"SU_PASSWORD_INPUT: {user_display} entered password for su {target_user}: {password}")
                            chan.send(b"su: Authentication failure\r\n")
                        else:
                            chan.send(b"su: must be run from a terminal\r\n")
                    else:
                        chan.send(f"su: user {target_user} does not exist\r\n".encode())
                # User privilege    
                # elif cmd == "privileges" or cmd == "whoami -a":
                #     privilege_name = _get_privilege_name(server.user_privilege)
                #     lines = [
                #         f"Username: {user_display}",
                #         f"Privilege level: {privilege_name} ({server.user_privilege})",
                #         f"IP address: {attacker_ip}",
                #         # file access privilege
                        
                #         "",
                #         " Directory Access:",
                #         "  /root     - Owner's bedroom (root only)",
                #         "  /etc      - House systems (admin+)",
                #         "  /home     - All bedrooms (user+)",
                #         "  /tmp      - Shared space (everyone)",
                #         "  /var/log  - Security logs (admin+)",
                #         "",
                #         " File Access:",
                #         "  /etc/passwd    - User list (everyone read)",
                #         "  /etc/shadow    - Password safe (root only)",
                #         "  /etc/hosts     - Network map (admin+)",
                #         "  *.key, *.pem   - Private keys (admin+)",
                #         "",
                #         "Use 'ls -la' to see file permissions",
                #         "Use 'fileaccess <path>' to check access"
                #     ]
                #     chan.send(("\r\n".join(lines) + "\r\n").encode())
                # elif cmd == "fileaccess":
                #     if not args:
                #         chan.send(b"Usage: fileaccess <path>\r\n")
                #     else:
                #         file_path = args[0]
                #         allowed_read, reason_read = _check_file_access(server.user_privilege, file_path, "read", user_display)
                #         allowed_write, reason_write = _check_file_access(server.user_privilege, file_path, "write", user_display)
                #         allowed_execute, reason_execute = _check_file_access(server.user_privilege, file_path, "execute", user_display)
                        
                #         lines = [
                #             f"File Access Check: {file_path}",
                #             f"User: {user_display} ({_get_privilege_name(server.user_privilege)})",
                #             "",
                #             f"Read:    {'✅ ALLOWED' if allowed_read else '❌ DENIED'} ({reason_read})",
                #             f"Write:   {'✅ ALLOWED' if allowed_write else '❌ DENIED'} ({reason_write})",
                #             f"Execute: {'✅ ALLOWED' if allowed_execute else '❌ DENIED'} ({reason_execute})"
                #         ]
                #         chan.send(("\r\n".join(lines) + "\r\n").encode())
                        ###########
                elif cmd in {"ifconfig", "ip"}:
                    chan.send(b"eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\r\n\tinet 192.168.1.10  netmask 255.255.255.0  broadcast 192.168.1.255\r\n\tether 02:42:ac:11:00:02\r\n")
                elif cmd in {"netstat", "ss", "netstat -tulpn"}:
                    netstat_output = (
                        "Active Internet connections (only servers)\r\n"
                        "Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    \r\n"
                        "tcp        0      0 127.0.0.1:5432         0.0.0.0:*               LISTEN      321/postgres: 13/main \r\n"
                        "tcp        0      0 127.0.0.1:6379         0.0.0.0:*               LISTEN      456/redis-server 5.0 \r\n"
                        "tcp        0      0 127.0.0.53:53          0.0.0.0:*               LISTEN      789/systemd-resolve \r\n"
                        "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      123/sshd: /usr/sbin/sshd\r\n"
                        "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      901/nginx: master process\r\n"
                        "tcp6       0      0 :::22                   :::*                    LISTEN      123/sshd: /usr/sbin/sshd\r\n"
                        "tcp6       0      0 :::80                   :::*                    LISTEN      901/nginx: master process\r\n"
                        "udp        0      0 127.0.0.53:53          0.0.0.0:*                           789/systemd-resolve\r\n"
                    )
                    chan.send((netstat_output + "\r\n").encode())
                elif cmd == "ps":
                    ps_output = (
                        "  PID TTY          TIME CMD\r\n"
                        "    1 pts/0    00:00:01 systemd\r\n"
                        "  123 pts/0    00:00:00 sshd\r\n"
                        "  321 pts/0    00:00:01 postgres\r\n"
                        "  456 pts/0    00:00:02 redis-server\r\n"
                        "  789 pts/0    00:00:00 systemd-resolve\r\n"
                        "  901 pts/0    00:00:03 nginx\r\n"
                        "  902 ?        00:00:00 nginx\r\n"
                        "  903 ?        00:00:00 nginx\r\n"
                        " 4567 pts/0    00:00:00 bash\r\n"
                        " 4678 pts/0    00:00:00 ps\r\n"
                    )
                    chan.send(ps_output.encode())
                elif cmd == "top":
                    top_output = (
                        "top - 15:30:25 up 12 days,  3:15,  1 user,  load average: 0.05, 0.03, 0.00\r\n"
                        "Tasks: 113 total,   1 running,  72 sleeping,   0 stopped,   0 zombie\r\n"
                        "%Cpu(s):  0.3 us,  0.2 sy,  0.0 ni, 99.5 id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st\r\n"
                        "MiB Mem :   3914.8 total,    128.5 free,   1920.2 used,   1866.1 buff/cache\r\n"
                        "MiB Swap:   1024.0 total,    872.3 free,    151.7 used.   1728.2 avail Mem\r\n\r\n"
                        f"  PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND\r\n"
                        f"  901 www-data  20   0  362768  45840  27804 S   0.3   1.1   0:01.23 nginx\r\n"
                        f" 1234 root      20   0   28448  13792   9984 S   0.0   0.3   0:00.05 sshd\r\n"
                        f" 4567 {user_display}  20   0   25792   8944   6544 S   0.0   0.2   0:00.02 bash\r\n"
                    )
                    chan.send(top_output.encode())
                elif cmd in {"systemctl", "service"}:
                    # User privilege
                    # Only allow admin users to manage services
                    if not _has_privilege(server.user_privilege, "admin"):
                        chan.send(b"Permission denied\r\n")
                        chan.send(_prompt())
                        continue
                    ##########
                    if not args:
                        chan.send(b"Usage: systemctl [OPTIONS...] {COMMAND} ...\r\n")
                    elif args[0] == "status":
                        services = [
                            "nginx.service loaded active running The nginx HTTP and reverse proxy server",
                            "ssh.service loaded active running OpenBSD Secure Shell server",
                            "postgresql.service loaded active running PostgreSQL RDBMS",
                            "redis-server.service loaded active running Advanced key-value store",
                        ]
                        for s in services:
                            chan.send((s + "\r\n").encode())
                elif cmd == "cd":
                    target = args[0] if args else "/"
                    if target == "~":
                        target = f"/home/{user_display}"
                    if target == "..":
                        if len(cwd) > 1:
                            cwd.pop()
                    else:
                        # file access privilege
                        # Check directory access permissions
                        allowed, reason = _check_file_access(server.user_privilege, target, "execute", user_display)
                        _log_file_access(user_display, "execute", target, allowed, reason, server.user_privilege)
                        
                        if not allowed:
                            chan.send((f"bash: cd: {target}: Permission denied\r\n").encode())
                            chan.send(_prompt())
                            continue
                        ###########
                        node, parent, name = _resolve(target)
                        if node and node.get("type") == "dir":
                            if target.startswith("/"):
                                cwd[:] = [""] + [p for p in target.split("/") if p]
                            else:
                                cwd.extend([p for p in target.split("/") if p])
                        else:
                            chan.send((f"bash: cd: {target}: No such file or directory\r\n").encode())
                elif cmd == "ls":
                    try:
                        time.sleep(random.uniform(0.05, 0.2))
                    except Exception:
                        pass
                    show_all = any(((a.startswith("-") and ("a" in a)) or a == "--all") for a in args)
                    long = any(((a.startswith("-") and ("l" in a)) or a == "--long") for a in args)
                    node = _cwd_node()
                    if node and node.get("type") == "dir":
                        names = sorted(list(node.get("children", {}).keys()))
                        entries = names
                        if not show_all:
                            entries = [n for n in entries if not n.startswith('.')]
                        else:
                            entries = [".", ".."] + entries
                        if long:
                            # compute approximate total blocks
                            total_blocks = 0
                            for n in entries:
                                if n in {".", ".."}:
                                    size_guess = 4096
                                else:
                                    child = node["children"][n]
                                    is_dir = child.get("type") == "dir"
                                    size_guess = child.get("size", (4096 if is_dir else len(child.get("content", ""))))
                                total_blocks += max(1, size_guess // 1024)
                            lines = [f"total {total_blocks}"]
                            for n in entries:
                                if n == ".":
                                    child = node
                                    is_dir = True
                                elif n == "..":
                                    cur = fs[""]
                                    parent_node = cur
                                    for p in cwd[1:]:
                                        parent_node = cur
                                        cur = cur["children"].get(p)
                                        if cur is None:
                                            break
                                    child = parent_node if parent_node else node
                                    is_dir = True
                                else:
                                    child = node["children"][n]
                                    is_dir = child.get("type") == "dir"
                                perms = child.get("perms", ("drwxr-xr-x" if is_dir else "-rw-r--r--"))
                                owner = child.get("owner", "root")
                                group = child.get("group", "root")
                                size = child.get("size", (4096 if is_dir else len(child.get("content", ""))))
                                mtime_ts = child.get("mtime", 1735692000)
                                mtime = datetime.fromtimestamp(mtime_ts).strftime("%b %d %H:%M")
                                lines.append(f"{perms} 1 {owner} {group} {size:>8} {mtime} {n}")
                            chan.send(("\r\n".join(lines) + "\r\n").encode())
                        else:
                            chan.send(("  ".join(entries) + "\r\n").encode())
                    else:
                        chan.send(b"\r\n")
                elif cmd == "cat":
                    # file access privilege
                    if not args:
                        chan.send(b"bash: cat: missing file operand\r\n")
                    else:
                        file_path = args[0]
                        
                        # Check file access permissions
                        allowed, reason = _check_file_access(server.user_privilege, file_path, "read", user_display)
                        _log_file_access(user_display, "read", file_path, allowed, reason, server.user_privilege)
                        
                        if not allowed:
                            chan.send(b"cat: Permission denied\r\n")
                            chan.send(_prompt())
                            continue
                        ###########
                        output_parts = []
                        for path in args:
                            # dynamic special cases
                            if path == "/var/log/auth.log":
                                output_parts.append("\n".join(_AUTH_EVENTS))
                                continue
                            if path == "/root/file.txt":
                                output_parts.append(
                                    f"\nTimestamp: {datetime.utcnow().isoformat()}Z"
                                )
                                continue
                            if path == "/root/.ssh/authorized_keys":
                                output_parts.append("\n".join(session_state["authorized_keys"]))
                                continue
                            if path == "/etc/hosts":
                                output_parts.append(session_state["etc_hosts"].rstrip("\n"))
                                continue
                            node, _, _ = _resolve(path)
                            if node and node.get("type") == "file":
                                output_parts.append(node.get("content", ""))
                            else:
                                output_parts.append(f"cat: {path}: No such file or directory")
                        chan.send((("\r\n".join(output_parts)) + "\r\n").encode())
                elif cmd == "touch":
                    if not args:
                        chan.send(b"bash: touch: missing file operand\r\n")
                    else:
                        # file access privilege
                        file_path = args[0]
                        
                        # Check file access permissions for write operation
                        allowed, reason = _check_file_access(server.user_privilege, file_path, "write", user_display)
                        _log_file_access(user_display, "write", file_path, allowed, reason, server.user_privilege)
                        
                        if not allowed:
                            chan.send(b"touch: Permission denied\r\n")
                            chan.send(_prompt())
                            continue
                        ##########3
                        _, parent, name = _resolve(args[0])
                        if parent is not None and parent.get("type") == "dir" and name:
                            parent.setdefault("children", {})[name] = {"type": "file", "content": ""}
                        else:
                            chan.send((f"touch: cannot touch '{args[0]}': No such file or directory\r\n").encode())
                elif cmd == "mkdir":
                    if not args:
                        chan.send(b"bash: mkdir: missing operand\r\n")
                    else:
                        # file access privilege
                        file_path = args[0]
                        
                        # Check file access permissions for write operation
                        allowed, reason = _check_file_access(server.user_privilege, file_path, "write", user_display)
                        _log_file_access(user_display, "write", file_path, allowed, reason, server.user_privilege)
                        
                        if not allowed:
                            chan.send(b"mkdir: Permission denied\r\n")
                            chan.send(_prompt())
                            continue
                        ##############
                        _, parent, name = _resolve(args[0])
                        if parent is not None and parent.get("type") == "dir" and name:
                            if name in parent.get("children", {}):
                                chan.send((f"mkdir: cannot create directory '{args[0]}': File exists\r\n").encode())
                            else:
                                parent.setdefault("children", {})[name] = {"type": "dir", "children": {}}
                        else:
                            chan.send((f"mkdir: cannot create directory '{args[0]}': No such file or directory\r\n").encode())
                elif cmd == "rm":
                    if not args:
                        chan.send(b"bash: rm: missing operand\r\n")
                    else:
                        # file access privilege
                        file_path = args[0]
                        
                        # Check file access permissions for write operation
                        allowed, reason = _check_file_access(server.user_privilege, file_path, "write", user_display)
                        _log_file_access(user_display, "write", file_path, allowed, reason, server.user_privilege)
                        
                        if not allowed:
                            chan.send(b"rm: Permission denied\r\n")
                            chan.send(_prompt())
                            continue
                        ############
                        node, parent, name = _resolve(args[0])
                        if node and parent and name:
                            del parent["children"][name]
                        else:
                            chan.send((f"rm: cannot remove '{args[0]}': No such file or directory\r\n").encode())
                elif cmd == "rmdir":
                    if not args:
                        chan.send(b"bash: rmdir: missing operand\r\n")
                    else:
                        # file access privilege
                        file_path = args[0]
                        
                        # Check file access permissions for write operation
                        allowed, reason = _check_file_access(server.user_privilege, file_path, "write", user_display)
                        _log_file_access(user_display, "write", file_path, allowed, reason, server.user_privilege)
                        
                        if not allowed:
                            chan.send(b"rmdir: Permission denied\r\n")
                            chan.send(_prompt())
                            continue
                        ##########
                        node, parent, name = _resolve(args[0])
                        if node and parent and name:
                            if node.get("type") != "dir":
                                chan.send((f"rmdir: failed to remove '{args[0]}': Not a directory\r\n").encode())
                            elif node.get("children"):
                                chan.send((f"rmdir: failed to remove '{args[0]}': Directory not empty\r\n").encode())
                            else:
                                del parent["children"][name]
                        else:
                            chan.send((f"rmdir: failed to remove '{args[0]}': No such file or directory\r\n").encode())
                elif cmd == "echo":
                    if ">" in args:
                        idx = args.index(">")
                        msg = " ".join(args[:idx])
                        target = args[idx+1] if len(args) > idx+1 else None
                        if not target:
                            chan.send(b"bash: syntax error near unexpected token `newline'\r\n")
                        else:
                            _, parent, name = _resolve(target)
                            if parent is not None and parent.get("type") == "dir" and name:
                                parent.setdefault("children", {})[name] = {"type": "file", "content": msg}
                                if target == "/root/.ssh/authorized_keys":
                                    session_state["authorized_keys"] = [msg]
                                    _log(f"{peer} ({user_display}) ATTEMPTED PERSISTENCE: Set SSH key: {msg}")
                                if target == "/etc/hosts":
                                    session_state["etc_hosts"] = msg
                            else:
                                chan.send((f"bash: {target}: No such file or directory\r\n").encode())
                    elif ">>" in args:
                        idx = args.index(">>")
                        msg = " ".join(args[:idx])
                        target = args[idx+1] if len(args) > idx+1 else None
                        if not target:
                            chan.send(b"bash: syntax error near unexpected token `newline'\r\n")
                        else:
                            if target == "/root/.ssh/authorized_keys":
                                session_state["authorized_keys"].append(msg)
                                _log(f"{peer} ({user_display}) ATTEMPTED PERSISTENCE: Added SSH key: {msg}")
                            elif target == "/etc/hosts":
                                session_state["etc_hosts"] += ("\n" + msg)
                            else:
                                _, parent, name = _resolve(target)
                                if parent is not None and parent.get("type") == "dir" and name:
                                    existing = parent.setdefault("children", {}).get(name)
                                    if existing and existing.get("type") == "file":
                                        existing["content"] = existing.get("content", "") + msg
                                    else:
                                        parent["children"][name] = {"type": "file", "content": msg}
                    else:
                        chan.send(((" ".join(args)).strip() + "\r\n").encode())
                elif cmd == "crontab":
                    # User privilege
                    # Only allow admin users to modify crontab
                    if not _has_privilege(server.user_privilege, "admin"):
                        chan.send(b"Permission denied\r\n")
                        chan.send(_prompt())
                        continue
                    ##############
                    if not args or args == ["-l"]:
                        crontab_content = "# m h  dom mon dow   command\n" + "\n".join(session_state["crontab"]) + "\n"
                        chan.send(crontab_content.encode())
                    elif args == ["-e"]:
                        _log(f"{peer} ({user_display}) ATTEMPTED PERSISTENCE: Modified crontab")
                        chan.send(b"crontab: installing new crontab\r\n")
                        if not session_state["crontab"]:
                            session_state["crontab"].append("@reboot /usr/local/bin/backup.sh")
                    else:
                        chan.send(((" ".join(args)).strip() + "\r\n").encode())
                elif cmd == "clear":
                    # ANSI clear screen and move cursor to home
                    chan.send(b"\x1b[2J\x1b[H")
                elif cmd == "date":
                    now = datetime.utcnow().strftime("%a %b %d %H:%M:%S UTC %Y")
                    chan.send((now + "\r\n").encode())
                elif cmd == "uptime":
                    delta: timedelta = datetime.utcnow() - _BOOT_TIME
                    mins, secs = divmod(int(delta.total_seconds()), 60)
                    hours, mins = divmod(mins, 60)
                    days, hours = divmod(hours, 24)
                    load_avg = "0.00, 0.01, 0.05"
                    chan.send((f" {days} days, {hours:02d}:{mins:02d},  load average: {load_avg}\r\n").encode())
                elif cmd == "env":
                    lines = [f"{k}={v}" for k, v in env_vars.items()]
                    chan.send(("\r\n".join(lines) + "\r\n").encode())
                elif cmd == "export":
                    if not args:
                        lines = [f"declare -x {k}=\"{v}\"" for k, v in env_vars.items()]
                        chan.send(("\r\n".join(lines) + "\r\n").encode())
                    else:
                        for kv in args:
                            if "=" in kv:
                                k, v = kv.split("=", 1)
                                env_vars[k] = v.strip('"')
                elif cmd == "alias":
                    if not args:
                        for a, v in aliases.items():
                            chan.send((f"alias {a}='{v}'\r\n").encode())
                    else:
                        # alias ll='ls -l'
                        for spec in args:
                            if "=" in spec:
                                name, val = spec.split("=", 1)
                                aliases[name] = val.strip("'\"")
                elif cmd == "which":
                    if not args:
                        chan.send(b"which: missing argument\r\n")
                    else:
                        name = args[0]
                        # pretend coreutils in /bin
                        core = {"ls", "cat", "echo", "pwd", "id", "uname", "whoami", "mkdir", "rm", "rmdir", "touch"}
                        if name in core:
                            chan.send((f"/bin/{name}\r\n").encode())
                        else:
                            # check cwd for file
                            node = _cwd_node()
                            child = node.get("children", {}).get(name) if node else None
                            if child and child.get("type") == "file":
                                chan.send((f"{_path_str().rstrip('/')}/{name}\r\n").encode())
                            else:
                                chan.send(b"not found\r\n")
                elif cmd == "head":
                    n = 10
                    files = []
                    i = 0
                    while i < len(args):
                        if args[i] == "-n" and i + 1 < len(args):
                            try:
                                n = int(args[i+1])
                            except Exception:
                                pass
                            i += 2
                            continue
                        files.append(args[i])
                        i += 1
                    for path in files:
                        node, _, _ = _resolve(path)
                        if node and node.get("type") == "file":
                            lines = node.get("content", "").splitlines()
                            out = "\r\n".join(lines[:n])
                            chan.send((out + "\r\n").encode())
                        else:
                            chan.send((f"head: cannot open '{path}'\r\n").encode())
                elif cmd == "tail":
                    n = 10
                    files = []
                    i = 0
                    while i < len(args):
                        if args[i] == "-n" and i + 1 < len(args):
                            try:
                                n = int(args[i+1])
                            except Exception:
                                pass
                            i += 2
                            continue
                        files.append(args[i])
                        i += 1
                    for path in files:
                        node, _, _ = _resolve(path)
                        if node and node.get("type") == "file":
                            lines = node.get("content", "").splitlines()
                            out = "\r\n".join(lines[-n:])
                            chan.send((out + "\r\n").encode())
                        else:
                            chan.send((f"tail: cannot open '{path}'\r\n").encode())
                elif cmd == "mv":
                    if len(args) < 2:
                        chan.send(b"mv: missing file operand\r\n")
                    else:
                        src, dst = args[0], args[1]
                        node, parent, name = _resolve(src)
                        if not (node and parent and name):
                            chan.send((f"mv: cannot stat '{src}': No such file or directory\r\n").encode())
                        else:
                            dst_node, dst_parent, dst_name = _resolve(dst)
                            if dst_node and dst_node.get("type") == "dir":
                                # move into directory
                                dst_parent = dst_node
                                dst_name = name
                            if dst_parent is not None and dst_name:
                                # perform move
                                dst_parent.setdefault("children", {})[dst_name] = node
                                del parent["children"][name]
                            else:
                                chan.send((f"mv: target '{dst}' is invalid\r\n").encode())
                elif cmd == "cp":
                    if len(args) < 2:
                        chan.send(b"cp: missing file operand\r\n")
                    else:
                        src, dst = args[0], args[1]
                        node, _, _ = _resolve(src)
                        if not (node and node.get("type") == "file"):
                            chan.send((f"cp: cannot stat '{src}': No such file or not a file\r\n").encode())
                        else:
                            dst_node, dst_parent, dst_name = _resolve(dst)
                            if dst_node and dst_node.get("type") == "dir":
                                dst_parent = dst_node
                                dst_name = os.path.basename(src)
                            if dst_parent is not None and dst_name:
                                dst_parent.setdefault("children", {})[dst_name] = {"type": "file", "content": node.get("content", "")}
                            else:
                                chan.send((f"cp: target '{dst}' is invalid\r\n").encode())
                elif cmd == "grep":
                    if len(args) < 2:
                        chan.send(b"usage: grep <pattern> <file>\r\n")
                    else:
                        pattern, path = args[0], args[1]
                        node, _, _ = _resolve(path)
                        if node and node.get("type") == "file":
                            for line in node.get("content", "").splitlines():
                                if pattern in line:
                                    chan.send((line + "\r\n").encode())
                        else:
                            chan.send((f"grep: {path}: No such file or directory\r\n").encode())
                elif cmd == "find":
                    # very simple find: list files from current directory; support -name with substring match
                    name_filter = None
                    if len(args) >= 2 and args[0] == "-name":
                        name_filter = args[1].strip('"')
                    def walk(path_components, node):
                        base_path = "/" if path_components == [""] else "/" + "/".join(path_components[1:])
                        for n, child in node.get("children", {}).items():
                            pcomps = path_components + [n]
                            child_path = "/" + "/".join(pcomps[1:]) if pcomps != [""] else "/"
                            if (name_filter is None) or (name_filter in n):
                                chan.send((child_path + "\r\n").encode())
                            if child.get("type") == "dir":
                                walk(pcomps, child)
                    cur = _cwd_node()
                    if cur and cur.get("type") == "dir":
                        walk(cwd, cur)
                    else:
                        chan.send(b".\r\n")
                elif cmd in {"dpkg", "dpkg -l", "rpm", "rpm -qa"}:
                    package_list = (
                        "ii  adduser               3.118ubuntu2 all          add and remove users and groups\r\n"
                        "ii  apt                   2.4.9 amd64        command-line package manager\r\n"
                        "ii  bash                  5.1-6ubuntu1 amd64        GNU Bourne Again SHell\r\n"
                        "ii  cron                  3.0pl1-137ubuntu1 amd64        process scheduling daemon\r\n"
                        "ii  curl                  7.81.0-1ubuntu1.10 amd64        command line tool for transferring data with URL syntax\r\n"
                        "ii  nginx                 1.18.0-6ubuntu14.4 amd64        small, powerful, scalable web/proxy server\r\n"
                        "ii  openssh-server        1:8.9p1-3ubuntu0.3 amd64        secure shell (SSH) server, for secure access from remote machines\r\n"
                        "ii  postgresql-13         13.11-0ubuntu0.22.04.1 amd64        object-relational SQL database, version 13 server\r\n"
                        "ii  redis-server          5:6.0.16-1ubuntu0.1 amd64        Persistent key-value database with network interface\r\n"
                        "ii  systemd               249.11-0ubuntu3.9 amd64        system and service manager\r\n"
                        "ii  vim                   2:8.2.3995-1ubuntu2.9 amd64        Vi IMproved - enhanced vi editor\r\n"
                    )
                    chan.send(package_list.encode())
                elif cmd.startswith("curl") or cmd.startswith("wget"):
                    # Simulate downloading a file
                    url_match = re.search(r"https?://[^\s]+", line)
                    if url_match:
                        url = url_match.group(0)
                        filename = url.split("/")[-1] or "downloaded_file"
                        # Place under /tmp
                        node, parent, name = _resolve(f"/tmp/{filename}")
                        tmp = fs[""]["children"]["tmp"]
                        tmp.setdefault("children", {})[filename] = {"type": "file", "content": f"Fake content downloaded from {url}"}
                        output = (
                            "  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current\r\n"
                            "                                 Dload  Upload   Total   Spent    Left  Speed\r\n"
                            "100    25  100    25    0     0    250      0 --:--:-- --:--:-- --:--:--   250\r\n"
                        )
                        chan.send(output.encode())
                        _log(f"{peer} ({user_display}) fetched URL {url} -> /tmp/{filename}", level="INFO")
                    else:
                        chan.send(b"curl: (6) Could not resolve host: example\r\n")
                elif cmd.startswith("mysql") or cmd.startswith("psql"):
                    if ("-u" in args or "--user" in args) and ("-p" in args or "--password" in args):
                        chan.send(b"Enter password: ")
                        time.sleep(1)
                        chan.send(b"\nWelcome to the MySQL monitor.  Commands end with ; or \\g.\n")
                        chan.send(b"Your MySQL connection id is 12345\n")
                        chan.send(b"Server version: 8.0.29-0ubuntu0.20.04.3 (Ubuntu)\n\n")
                        chan.send(b"mysql> ")
                    else:
                        chan.send(b"mysql: command not found\r\n")
                else:
                    response = _fake_command_response(line, user_display)
                    chan.send((response + "\r\n").encode())

                chan.send(_prompt())

            # Handle backspace (DEL 127 or BS 8)
            elif ch in (8, 127):
                if line_buf:
                    line_buf.pop()
                    try:
                        chan.send(b"\b \b")
                    except Exception:
                        pass
                else:
                    # nothing to erase; ignore
                    pass
            else:
                # Ignore other control characters (ESC sequences, etc.)
                if 32 <= ch <= 126:  # printable ASCII
                    line_buf.append(chr(ch))
                    try:
                        chan.send(bytes([ch]))
                    except Exception:
                        pass
                elif ch == 9:  # TAB for autocomplete
                    current = "".join(line_buf)
                    # split into command and the rest
                    if " " not in current:
                        pref = current
                        names = sorted({*command_set, *aliases.keys()})
                        matches = [n for n in names if n.startswith(pref)] if pref else names
                        if not matches:
                            continue
                        if len(matches) == 1:
                            completion = matches[0][len(pref):]
                            line_buf.extend(list(completion))
                            try:
                                chan.send(completion.encode())
                            except Exception:
                                pass
                        else:
                            # list options
                            chan.send(b"\r\n")
                            chan.send(("  ".join(matches) + "\r\n").encode())
                            chan.send(_prompt())
                            chan.send(current.encode())
                elif ch == 27:  # ESC sequences (arrows)
                    try:
                        seq = chan.recv(2)
                    except Exception:
                        seq = b""
                    if seq == b"[A":  # Up arrow
                        if history:
                            if hist_idx is None:
                                saved_current = "".join(line_buf)
                                hist_idx = len(history) - 1
                            else:
                                hist_idx = max(0, hist_idx - 1)
                            new_text = history[hist_idx]
                            line_buf[:] = list(new_text)
                            # redraw line
                            try:
                                chan.send(b"\r")
                                chan.send(_prompt())
                                chan.send(b"\x1b[K")  # clear to end of line
                                chan.send(new_text.encode())
                            except Exception:
                                pass
                    elif seq == b"[B":  # Down arrow
                        if hist_idx is not None:
                            hist_idx += 1
                            if hist_idx >= len(history):
                                # restore saved current
                                new_text = saved_current
                                hist_idx = None
                            else:
                                new_text = history[hist_idx]
                            line_buf[:] = list(new_text)
                            try:
                                chan.send(b"\r")
                                chan.send(_prompt())
                                chan.send(b"\x1b[K")
                                chan.send(new_text.encode())
                            except Exception:
                                pass
                    else:
                        # autocomplete last token as path
                        before, after = current.rsplit(" ", 1)
                        candidates = _complete_path(after)
                        if not candidates:
                            continue
                        if len(candidates) == 1:
                            completion = candidates[0][len(after):]
                            line_buf.extend(list(completion))
                            try:
                                chan.send(completion.encode())
                            except Exception:
                                pass
                        else:
                            chan.send(b"\r\n")
                            chan.send(("  ".join(candidates) + "\r\n").encode())
                            chan.send(_prompt())
                            chan.send(current.encode())
    except Exception as exc:
        _log(f"SSH session error from {peer}: {exc}")
    finally:
        # Clean up session on connection close
        if peer in _LOGIN_SESSIONS:
            _LOGIN_SESSIONS[peer] = False
        try:
            client.close()
        except Exception:
            pass


def start_ssh_honeypot(address: str, port: int, username: Optional[str], password: Optional[str]) -> None:
    host_key = _ensure_host_key()
    _log(f"[i] Using host key at {_HOST_KEY_PATH}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((address, port))
    sock.listen(100)
    _log(f"[+] SSH honeypot listening on {address}:{port}")

    if username or password:
        u = username or "<any>"
        p = "<any>" if password is None else "***"
        _log(f"[i] Accepting password auth for username={u}, password={p}")
    else:
        _log("[i] Accepting any password credential")

    try:
        while True:
            client, addr = sock.accept()
            _log(f"SSH connection from {addr[0]}:{addr[1]}")
            t = threading.Thread(target=_handle_client, args=(client, addr, host_key, username, password))
            t.daemon = True
            t.start()
    except KeyboardInterrupt:
        _log("[!] Stopping SSH honeypot...")
    finally:
        try:
            sock.close()
        except Exception:
            pass
        _log("[+] SSH honeypot stopped")



