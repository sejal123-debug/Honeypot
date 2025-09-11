import socket
import threading
import time
import random
import os
import json
import hashlib
import shutil
from datetime import datetime
from typing import Optional, Tuple, Dict, Any, List

# User privilege levels
_FTP_PRIVILEGE_LEVELS = {
    "guest": 0,      # Limited access
    "user": 1,       # Standard user
    "admin": 2,      # Administrative access
    "root": 3        # Full system access
}

# Default user privileges mapping
_FTP_USER_PRIVILEGES = {
    "admin": "admin",
    "root": "root",
    "test": "user",
    "user": "user",
    "guest": "guest"
}

# Root-only directories and files (only accessible to root users)
_ROOT_ONLY_PATHS = {
    "/etc",
    "/etc/passwd",
    "/etc/shadow", 
    "/etc/hosts",
    "/var",
    "/var/log",
    "/var/log/auth.log",
    "/var/log/ftp.log",
    "/tmp",
    "/root",
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
    "/boot",
    "/proc",
    "/sys"
}

# Sensitive files that require admin or higher privileges
_ADMIN_ONLY_FILES = {
    "passwd",
    "shadow", 
    "hosts",
    "config",
    "credentials",
    "key",
    "pem",
    "p12",
    "db",
    "sql",
    "bak",
    "backup"
}

_LOG_FILE_PATH = __file__.replace("ftp_honeypot.py", "honeypot.log")
_STRUCTURED_LOG_PATH = __file__.replace("ftp_honeypot.py", "ftp_honeypot_structured.log")
_LOG_LOCK = threading.Lock()

# Global tracking for rate limiting and brute force protection
_failed_attempts: Dict[str, list] = {}
_banned_ips: set = set()

# Global tracking for failed attempts per IP (for 5 attempts feature)
_FTP_FAILED_ATTEMPTS: Dict[str, int] = {}
_FTP_LOGIN_SESSIONS: Dict[str, bool] = {}  # Track if IP has successfully logged in


def _log(message: str, level: str = "INFO", source: str = "FTP") -> None:
    ts = datetime.utcnow().isoformat()
    line = f"[{ts}Z] [{level}] [{source}] {message}"
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


def _structured_log(event_type: str, details: Dict[str, Any], source_ip: str, username: str = None, session_id: str = None) -> None:
    """Enhanced structured logging for analysis"""
    log_entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "source_ip": source_ip,
        "username": username,
        "event_type": event_type,
        "details": details,
        "session_id": session_id
    }
    try:
        with _LOG_LOCK:
            with open(_STRUCTURED_LOG_PATH, "a", encoding="utf-8") as f:
                json.dump(log_entry, f)
                f.write("\n")
    except Exception:
        pass


def _get_geoip_info(ip: str) -> str:
    """Get geographical information for IP (placeholder implementation)"""
    # In a real implementation, you would use geoip2 or similar
    # For now, return a placeholder
    if ip.startswith("127.") or ip.startswith("192.168.") or ip.startswith("10."):
        return "Local Network"
    return "Unknown location"


def _check_brute_force(ip: str) -> bool:
    """Check if IP should be banned for brute force attempts"""
    if ip in _banned_ips:
        return True
    
    if ip not in _failed_attempts:
        _failed_attempts[ip] = []
    
    # Remove old attempts (older than 5 minutes)
    current_time = time.time()
    _failed_attempts[ip] = [t for t in _failed_attempts[ip] if current_time - t < 300]
    
    # Check if too many recent attempts
    if len(_failed_attempts[ip]) > 5:
        _banned_ips.add(ip)
        _log(f"Banning {ip} for brute force attempts", level="ALERT")
        _structured_log("BRUTE_FORCE_BAN", {"ip": ip, "attempts": len(_failed_attempts[ip])}, ip)
        return True
    return False


def _record_failed_attempt(ip: str) -> None:
    """Record a failed authentication attempt"""
    if ip not in _failed_attempts:
        _failed_attempts[ip] = []
    _failed_attempts[ip].append(time.time())

# User privilege
def _ftp_has_privilege(user_privilege: int, required_privilege: str) -> bool:
    """Check if user has required privilege level"""
    return user_privilege >= _FTP_PRIVILEGE_LEVELS.get(required_privilege, 0)


def _ftp_get_privilege_name(privilege_level: int) -> str:
    """Convert privilege level to name"""
    for name, level in _FTP_PRIVILEGE_LEVELS.items():
        if level == privilege_level:
            return name
    return "guest"


def _check_ftp_file_access(user_privilege: int, file_path: str, operation: str, username: str) -> tuple[bool, str]:
    """
    Check if user has permission to access a file/directory in FTP
    Returns (allowed, reason)
    """
    # Normalize path
    if not file_path.startswith("/"):
        file_path = "/" + file_path
    
    # Root user (privilege level 3) can access everything
    if user_privilege >= _FTP_PRIVILEGE_LEVELS["root"]:
        return True, "root_access"
    
    # Check for root-only paths
    for root_path in _ROOT_ONLY_PATHS:
        if file_path.startswith(root_path) or file_path == root_path:
            _log(f"FTP_ACCESS_DENIED: {username} ({_ftp_get_privilege_name(user_privilege)}) attempted {operation} on root-only path: {file_path}", level="WARNING")
            return False, f"Root-only path access denied: {root_path}"
    
    # Check for admin-only files based on filename
    filename = os.path.basename(file_path).lower()
    for sensitive in _ADMIN_ONLY_FILES:
        if sensitive in filename:
            if user_privilege < _FTP_PRIVILEGE_LEVELS["admin"]:
                _log(f"FTP_ACCESS_DENIED: {username} ({_ftp_get_privilege_name(user_privilege)}) attempted {operation} on admin-only file: {file_path}", level="WARNING")
                return False, f"Admin-only file access denied: {filename}"
            break
    
    # Guest users can access /ftp directory and subdirectories, including /ftp/users and users.txt
    if user_privilege == _FTP_PRIVILEGE_LEVELS["guest"]:
        if not file_path.startswith("/ftp") and file_path != "/" and file_path != "/ftp":
            _log(f"FTP_ACCESS_DENIED: {username} (guest) attempted {operation} outside /ftp: {file_path}", level="WARNING")
            return False, "Guest access limited to /ftp directory"
        
        # Special case: Allow guest users to access /ftp/users and users.txt
        if file_path.startswith("/ftp/users") or file_path == "/ftp/users" or file_path == "/ftp/users/users.txt":
            return True, "guest_users_directory_access"
    
    # Regular users can access /ftp and /home directories
    if user_privilege == _FTP_PRIVILEGE_LEVELS["user"]:
        if not (file_path.startswith("/ftp") or file_path.startswith("/home") or file_path == "/" or file_path == "/ftp" or file_path == "/home"):
            _log(f"FTP_ACCESS_DENIED: {username} (user) attempted {operation} outside allowed directories: {file_path}", level="WARNING")
            return False, "User access limited to /ftp and /home directories"
    
    # Admin users can access most areas except root-only paths (already checked above)
    if user_privilege >= _FTP_PRIVILEGE_LEVELS["admin"]:
        return True, "admin_access"
    
    return True, "allowed_access"


def _set_user_home_directory(fs, username: str, user_privilege: int) -> str:
    """
    Set the user's default home directory after login
    Returns the path where the user was set
    """
    # Determine home directory based on user privilege
    if user_privilege >= _FTP_PRIVILEGE_LEVELS["root"]:
        # Root users go to /root
        home_path = "/root"
    elif user_privilege >= _FTP_PRIVILEGE_LEVELS["user"]:
        # Regular users and admins go to /home/{username}
        home_path = f"/home/{username}"
    else:
        # Guest users go to /ftp
        home_path = "/ftp"
    
    # Try to change to the home directory
    if fs.cwd_to(home_path):
        _log(f"FTP_HOME_DIRECTORY: {username} ({_ftp_get_privilege_name(user_privilege)}) set home directory to {home_path}")
        return home_path
    else:
        # Fallback to /ftp if home directory doesn't exist
        if fs.cwd_to("/ftp"):
            _log(f"FTP_HOME_DIRECTORY: {username} ({_ftp_get_privilege_name(user_privilege)}) fallback to /ftp (home directory {home_path} not available)")
            return "/ftp"
        else:
            # Last resort - stay at root
            _log(f"FTP_HOME_DIRECTORY: {username} ({_ftp_get_privilege_name(user_privilege)}) staying at root (no accessible home directory)")
            return "/"


def _ensure_upload_directory():
    """Ensure the upload directory exists"""
    upload_dir = "ftp_uploads"
    if not os.path.exists(upload_dir):
        os.makedirs(upload_dir)
        _log(f"Created upload directory: {upload_dir}")
    return upload_dir


def _save_uploaded_file(filename: str, content: bytes, username: str) -> str:
    """Save uploaded file to real filesystem"""
    try:
        upload_dir = _ensure_upload_directory()
        
        # Create user-specific subdirectory
        user_dir = os.path.join(upload_dir, username)
        if not os.path.exists(user_dir):
            os.makedirs(user_dir)
        
        # Generate unique filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name, ext = os.path.splitext(filename)
        unique_filename = f"{base_name}_{timestamp}{ext}"
        file_path = os.path.join(user_dir, unique_filename)
        
        # Save the file
        with open(file_path, 'wb') as f:
            f.write(content)
        
        _log(f"REAL_FILE_SAVED: {username} uploaded {filename} -> {file_path} ({len(content)} bytes)")
        return file_path
        
    except Exception as e:
        _log(f"Error saving uploaded file {filename}: {e}", level="ERROR")
        return ""


def _list_uploaded_files(username: str = None) -> List[str]:
    """List all uploaded files, optionally filtered by username"""
    try:
        upload_dir = _ensure_upload_directory()
        files = []
        
        if username:
            # List files for specific user
            user_dir = os.path.join(upload_dir, username)
            if os.path.exists(user_dir):
                for filename in os.listdir(user_dir):
                    file_path = os.path.join(user_dir, filename)
                    if os.path.isfile(file_path):
                        files.append(file_path)
        else:
            # List all files from all users
            for user_dir in os.listdir(upload_dir):
                user_path = os.path.join(upload_dir, user_dir)
                if os.path.isdir(user_path):
                    for filename in os.listdir(user_path):
                        file_path = os.path.join(user_path, filename)
                        if os.path.isfile(file_path):
                            files.append(file_path)
        
        return files
    except Exception as e:
        _log(f"Error listing uploaded files: {e}", level="ERROR")
        return []


def _generate_upload_summary():
    """Generate a summary of all uploaded files"""
    try:
        uploaded_files = _list_uploaded_files()
        if not uploaded_files:
            return "No files uploaded yet."
        
        total_files = len(uploaded_files)
        total_size = sum(os.path.getsize(f) for f in uploaded_files)
        
        # Group by user
        user_files = {}
        for file_path in uploaded_files:
            user = os.path.basename(os.path.dirname(file_path))
            if user not in user_files:
                user_files[user] = []
            user_files[user].append(file_path)
        
        summary = f"Upload Summary: {total_files} files, {total_size} bytes total\n"
        for user, files in user_files.items():
            user_size = sum(os.path.getsize(f) for f in files)
            summary += f"  {user}: {len(files)} files, {user_size} bytes\n"
        
        return summary
    except Exception as e:
        _log(f"Error generating upload summary: {e}", level="ERROR")
        return "Error generating summary."


def _ensure_download_directory():
    """Ensure the download directory exists"""
    download_dir = "ftp_downloads"
    if not os.path.exists(download_dir):
        os.makedirs(download_dir)
        _log(f"Created download directory: {download_dir}")
    return download_dir


def _save_downloaded_file(filename: str, content: bytes, username: str) -> str:
    """Save downloaded file to real filesystem"""
    try:
        download_dir = _ensure_download_directory()
        
        # Create user-specific subdirectory
        user_dir = os.path.join(download_dir, username)
        if not os.path.exists(user_dir):
            os.makedirs(user_dir)
        
        # Generate unique filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name, ext = os.path.splitext(filename)
        unique_filename = f"{base_name}_{timestamp}{ext}"
        file_path = os.path.join(user_dir, unique_filename)
        
        # Save the file
        with open(file_path, 'wb') as f:
            f.write(content)
        
        _log(f"REAL_FILE_DOWNLOADED: {username} downloaded {filename} -> {file_path} ({len(content)} bytes)")
        return file_path
        
    except Exception as e:
        _log(f"Error saving downloaded file {filename}: {e}", level="ERROR")
        return ""


def _list_downloaded_files(username: str = None) -> List[str]:
    """List all downloaded files, optionally filtered by username"""
    try:
        download_dir = _ensure_download_directory()
        files = []
        
        if username:
            # List files for specific user
            user_dir = os.path.join(download_dir, username)
            if os.path.exists(user_dir):
                for filename in os.listdir(user_dir):
                    file_path = os.path.join(user_dir, filename)
                    if os.path.isfile(file_path):
                        files.append(file_path)
        else:
            # List all files from all users
            for user_dir in os.listdir(download_dir):
                user_path = os.path.join(download_dir, user_dir)
                if os.path.isdir(user_path):
                    for filename in os.listdir(user_path):
                        file_path = os.path.join(user_path, filename)
                        if os.path.isfile(file_path):
                            files.append(file_path)
        
        return files
    except Exception as e:
        _log(f"Error listing downloaded files: {e}", level="ERROR")
        return []


def _generate_download_summary():
    """Generate a summary of all downloaded files"""
    try:
        downloaded_files = _list_downloaded_files()
        if not downloaded_files:
            return "No files downloaded yet."
        
        total_files = len(downloaded_files)
        total_size = sum(os.path.getsize(f) for f in downloaded_files)
        
        # Group by user
        user_files = {}
        for file_path in downloaded_files:
            user = os.path.basename(os.path.dirname(file_path))
            if user not in user_files:
                user_files[user] = []
            user_files[user].append(file_path)
        
        summary = f"Download Summary: {total_files} files, {total_size} bytes total\n"
        for user, files in user_files.items():
            user_size = sum(os.path.getsize(f) for f in files)
            summary += f"  {user}: {len(files)} files, {user_size} bytes\n"
        
        return summary
    except Exception as e:
        _log(f"Error generating download summary: {e}", level="ERROR")
        return "Error generating summary."
##############

def _generate_realistic_file(filename: str, size: int) -> bytes:
    """Generate realistic file content based on filename and size"""
    if filename.endswith('.txt'):
        content = f"This appears to be a real text file: {filename}\n"
        # content += "Generated by honeypot for security research.\n" * (size // 50)
        return content.encode()
    elif filename.endswith('.zip'):
        # Generate fake ZIP header
        content = b"PK\x03\x04" + os.urandom(max(0, size - 4))
        return content
    elif filename.endswith('.sql'):
        content = f"-- Database dump for {filename}\n"
        content += "CREATE TABLE users (id INT, username VARCHAR(50));\n" * (size // 60)
        return content.encode()
    elif filename.endswith('.bak') or filename.endswith('.backup'):
        content = f"Backup file: {filename}\n"
        content += "Backup created: " + datetime.utcnow().isoformat() + "\n"
        content += "X" * (size - len(content.encode()))
        return content.encode()
    elif filename.endswith('.config') or filename.endswith('.conf'):
        content = f"# Configuration file: {filename}\n"
        content += "server_name=example.com\n"
        content += "port=8080\n" * (size // 20)
        return content.encode()
    else:
        # Generic binary content
        return os.urandom(size)


class _FakeFS:
    def __init__(self) -> None:
        # Enhanced realistic filesystem structure
        current_time = int(time.time())
        self.tree = {
            "": {  # root
                "type": "dir",
                "owner": "root", "group": "root", "perms": "drwxr-xr-x", "mtime": current_time - 86400,
                "children": {
                    "etc": {
                        "type": "dir", "owner": "root", "group": "root", "perms": "drwxr-xr-x", "mtime": current_time - 86400,
                        "children": {
                            "passwd": {"type": "file", "size": 100, "owner": "root", "group": "root", "perms": "-rw-r--r--", "mtime": current_time - 86400, "content": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nftp:x:14:50:FTP User:/var/ftp:/sbin/nologin\n"},
                            "shadow": {"type": "file", "size": 150, "owner": "root", "group": "shadow", "perms": "-rw-r-----", "mtime": current_time - 86400, "content": "root:*:18659:0:99999:7:::\ndaemon:*:18659:0:99999:7:::\nftp:*:18659:0:99999:7:::\n"},
                            "hosts": {"type": "file", "size": 200, "owner": "root", "group": "root", "perms": "-rw-r--r--", "mtime": current_time - 43200, "content": "127.0.0.1 localhost\n192.168.1.1 router\n"},
                        }
                    },
                    "home": {
                        "type": "dir", "owner": "root", "group": "root", "perms": "drwxr-xr-x", "mtime": current_time - 86400,
                        "children": {
                            "admin": {
                                "type": "dir", "owner": "admin", "group": "admin", "perms": "drwxr-xr-x", "mtime": current_time - 43200,
                                "children": {
                                    "admin_notes.txt": {"type": "file", "size": 512, "owner": "admin", "group": "admin", "perms": "-rw-r--r--", "mtime": current_time - 3600, "content": _generate_realistic_file("admin_notes.txt", 512)},
                                    "config_backup": {"type": "dir", "owner": "admin", "group": "admin", "perms": "drwxr-xr-x", "mtime": current_time - 7200, "children": {}},
                                    "scripts": {"type": "dir", "owner": "admin", "group": "admin", "perms": "drwxr-xr-x", "mtime": current_time - 1800, "children": {}},
                                }
                            },
                            "root": {
                                "type": "dir", "owner": "root", "group": "root", "perms": "drwxr-xr-x", "mtime": current_time - 86400,
                                "children": {
                                    ".bashrc": {"type": "file", "size": 256, "owner": "root", "group": "root", "perms": "-rw-r--r--", "mtime": current_time - 86400, "content": _generate_realistic_file(".bashrc", 256)},
                                    ".profile": {"type": "file", "size": 128, "owner": "root", "group": "root", "perms": "-rw-r--r--", "mtime": current_time - 86400, "content": _generate_realistic_file(".profile", 128)},
                                    "system_logs": {"type": "dir", "owner": "root", "group": "root", "perms": "drwxr-xr-x", "mtime": current_time - 3600, "children": {}},
                                }
                            },
                            "user": {
                                "type": "dir", "owner": "user", "group": "user", "perms": "drwxr-xr-x", "mtime": current_time - 43200,
                                "children": {
                                    "documents": {"type": "dir", "owner": "user", "group": "user", "perms": "drwxr-xr-x", "mtime": current_time - 3600, "children": {}},
                                    "backup.zip": {"type": "file", "size": 2048, "owner": "user", "group": "user", "perms": "-rw-r--r--", "mtime": current_time - 7200, "content": _generate_realistic_file("backup.zip", 2048)},
                                    "database.sql": {"type": "file", "size": 1024, "owner": "user", "group": "user", "perms": "-rw-r--r--", "mtime": current_time - 1800, "content": _generate_realistic_file("database.sql", 1024)},
                                }
                            },
                            "test": {
                                "type": "dir", "owner": "test", "group": "test", "perms": "drwxr-xr-x", "mtime": current_time - 43200,
                                "children": {
                                    "test_file.txt": {"type": "file", "size": 256, "owner": "test", "group": "test", "perms": "-rw-r--r--", "mtime": current_time - 3600, "content": _generate_realistic_file("test_file.txt", 256)},
                                    "temp": {"type": "dir", "owner": "test", "group": "test", "perms": "drwxr-xr-x", "mtime": current_time - 1800, "children": {}},
                                }
                            },
                            "guest": {
                                "type": "dir", "owner": "guest", "group": "guest", "perms": "drwxr-xr-x", "mtime": current_time - 43200,
                                "children": {
                                    "readme.txt": {"type": "file", "size": 128, "owner": "guest", "group": "guest", "perms": "-rw-r--r--", "mtime": current_time - 3600, "content": _generate_realistic_file("readme.txt", 128)},
                                }
                            },
                            "ftp": {
                                "type": "dir", "owner": "ftp", "group": "ftp", "perms": "drwxr-xr-x", "mtime": current_time - 86400,
                                "children": {
                                    "users.txt": {"type": "file", "size": 1024, "owner": "ftp", "group": "ftp", "perms": "-rw-r--r--", "mtime": current_time - 86400, "content": _generate_realistic_file("users.txt", 1024)},
                                    "file2.txt": {"type": "file", "size": 2048, "owner": "ftp", "group": "ftp", "perms": "-rw-r--r--", "mtime": current_time - 43200, "content": _generate_realistic_file("file2.txt", 2048)},
                                    "config.conf": {"type": "file", "size": 512, "owner": "ftp", "group": "ftp", "perms": "-rw-r--r--", "mtime": current_time - 21600, "content": _generate_realistic_file("config.conf", 512)},
                                    "subdir": {"type": "dir", "owner": "ftp", "group": "ftp", "perms": "drwxr-xr-x", "mtime": current_time - 100000, "children": {}},
                                }
                            }
                        }
                    },
                    "var": {
                        "type": "dir", "owner": "root", "group": "root", "perms": "drwxr-xr-x", "mtime": current_time - 86400,
                        "children": {
                            "log": {
                                "type": "dir", "owner": "root", "group": "root", "perms": "drwxr-xr-x", "mtime": current_time - 3600,
                                "children": {
                                    "auth.log": {"type": "file", "size": 2048, "owner": "root", "group": "adm", "perms": "-rw-r-----", "mtime": current_time - 300, "content": "Jan 1 12:00:00 server sshd[1234]: Accepted password for root from 192.168.1.100\n"},
                                    "ftp.log": {"type": "file", "size": 1024, "owner": "root", "group": "adm", "perms": "-rw-r-----", "mtime": current_time - 600, "content": "Jan 1 12:00:00 ftpd: Connection from 192.168.1.100\n"},
                                }
                            }
                        }
                    },
                    "tmp": {
                        "type": "dir", "owner": "root", "group": "root", "perms": "drwxrwxrwt", "mtime": current_time - 3600,
                        "children": {}
                    },
                    "users.txt": {"type": "file", "size": 1024, "owner": "ftp", "group": "ftp", "perms": "-rw-r--r--", "mtime": current_time - 86400, "content": _generate_realistic_file("users.txt", 1024)},
                    "file2.txt": {"type": "file", "size": 2048, "owner": "ftp", "group": "ftp", "perms": "-rw-r--r--", "mtime": current_time - 43200, "content": _generate_realistic_file("file2.txt", 2048)},
                    "test.txt": {"type": "file", "size": 512, "owner": "ftp", "group": "ftp", "perms": "-rw-r--r--", "mtime": current_time - 21600, "content": _generate_realistic_file("test.txt", 512)},
                    "oldname.txt": {"type": "file", "size": 256, "owner": "ftp", "group": "ftp", "perms": "-rw-r--r--", "mtime": current_time - 10800, "content": _generate_realistic_file("oldname.txt", 256)},
                    "ftp": {
                        "type": "dir", "owner": "ftp", "group": "ftp", "perms": "drwxr-xr-x", "mtime": current_time - 86400,
                        "children": {
                            "backups": {
                                "type": "dir", "owner": "ftp", "group": "ftp", "perms": "drwxr-xr-x", "mtime": current_time - 43200,
                                "children": {
                                    "db-backup-2024-07-15.sql": {
                                        "type": "file", "size": 1200, "owner": "ftp", "group": "ftp", "perms": "-rw-r--r--", 
                                        "mtime": current_time - 43200, 
                                        "content": """-- MySQL dump 10.13  Distrib 8.0.28, for Linux (x86_64)
--
-- Host: localhost    Database: companydb
-- ------------------------------------------------------
-- Server version	8.0.28

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
CREATE DATABASE IF NOT EXISTS `companydb` /*!40100 DEFAULT CHARACTER SET utf8mb4 */;
USE `companydb`;

DROP TABLE IF EXISTS `users`;
CREATE TABLE `users` (
  `id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(50) DEFAULT NULL,
  `password` varchar(255) DEFAULT NULL,
  `role` varchar(20) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO `users` VALUES
(1,'jdoe','5f4dcc3b5aa765d61d8327deb882cf99','admin'),
(2,'asmith','e99a18c428cb38d5f260853678922e03','user'),
(3,'rkumar','098f6bcd4621d373cade4e832627b4f6','finance');

-- Dump completed on 2024-07-15 12:34:56"""
                                    }
                                }
                            },
                            "finance": {
                                "type": "dir", "owner": "ftp", "group": "ftp", "perms": "drwxr-xr-x", "mtime": current_time - 3600,
                                "children": {
                                    "Q3-report.xlsx": {
                                        "type": "file", "size": 200, "owner": "ftp", "group": "ftp", "perms": "-rw-r--r--", 
                                        "mtime": current_time - 3600, 
                                        "content": """Department,Revenue,Expenses,Profit
Finance, 120000, 75000, 45000
IT, 90000, 60000, 30000
Sales, 200000, 145000, 55000
HR, 40000, 25000, 15000"""
                                    },
                                    "salary-data.csv": {
                                        "type": "file", "size": 150, "owner": "ftp", "group": "ftp", "perms": "-rw-r--r--", 
                                        "mtime": current_time - 1800, 
                                        "content": """Name,Salary,Department
John Doe,85000,Finance
Alice Smith,91000,IT
Rahul Kumar,72000,HR
Maria Lopez,95000,Sales"""
                                    },
                                    "tax2023.docx": {
                                        "type": "file", "size": 300, "owner": "ftp", "group": "ftp", "perms": "-rw-r--r--", 
                                        "mtime": current_time - 7200, 
                                        "content": """CONFIDENTIAL - TAX DOCUMENT

Company: ACME Corp
FY: 2023
Prepared by: Finance Team

Key Notes:
- Pending VAT adjustments: $15,000
- Depreciation updated
- Payroll reconciliation under review"""
                                    }
                                }
                            },
                            "projects": {
                                "type": "dir", "owner": "ftp", "group": "ftp", "perms": "drwxr-xr-x", "mtime": current_time - 21600,
                                "children": {
                                    "webapp": {
                                        "type": "dir", "owner": "ftp", "group": "ftp", "perms": "drwxr-xr-x", "mtime": current_time - 21600,
                                        "children": {
                                            "config.php": {
                                                "type": "file", "size": 400, "owner": "ftp", "group": "ftp", "perms": "-rw-r--r--", 
                                                "mtime": current_time - 21600, 
                                                "content": """<?php
// Database configuration
$db_host = "192.168.1.50";
$db_user = "reporting_user";
$db_pass = "SuperSecret!2024"; // FAKE CREDENTIAL
$db_name = "companydb";

$api_endpoint = "https://api.fakecorp.local/v1";
$api_key = "sk_test_FAKE987654321"; // HONEYTOKEN
?>"""
                                            },
                                            "db_credentials.txt": {
                                                "type": "file", "size": 80, "owner": "ftp", "group": "ftp", "perms": "-rw-r--r--", 
                                                "mtime": current_time - 21600, 
                                                "content": """DB_HOST=192.168.1.50
DB_USER=readonly
DB_PASS=Finance@2024"""
                                            }
                                        }
                                    },
                                    "old-api": {
                                        "type": "dir", "owner": "ftp", "group": "ftp", "perms": "drwxr-xr-x", "mtime": current_time - 43200,
                                        "children": {
                                            "notes.txt": {
                                                "type": "file", "size": 200, "owner": "ftp", "group": "ftp", "perms": "-rw-r--r--", 
                                                "mtime": current_time - 43200, 
                                                "content": """- Old API endpoints were deprecated in 2023
- Keys stored in api_key.txt
- Reminder: migrate clients to /v2/ by end of year"""
                                            },
                                            "api_key.txt": {
                                                "type": "file", "size": 50, "owner": "ftp", "group": "ftp", "perms": "-rw-r--r--", 
                                                "mtime": current_time - 43200, 
                                                "content": """API_KEY=AIzaSyFAKE-1234567890abcdef"""
                                            }
                                        }
                                    }
                                }
                            },
                             "users": {
                                 "type": "dir", "owner": "ftp", "group": "ftp", "perms": "drwxr-xr-x", "mtime": current_time - 86400,
                                 "children": {
                                     "users.txt": {
                                         "type": "file", "size": 800, "owner": "ftp", "group": "ftp", "perms": "-rw-r--r--", 
                                         "mtime": current_time - 3600, 
                                         "content": """# System Users List
# All users present in the system

john:rabbit
admin:horse@123
root:root
user:user
test:test
guest:guest
demo:demo
temp:temp
admin:AdminPass2024!
root:RootPassword123!
john.doe:Password123!
jane.smith:Welcome2024
mike:SecurePass1
sarah.jones:MyPassword123
david.brown:Brown2024!
lisa:LisaPass123
robert.taylor:Robert123
amanda.white:Amanda2024
chris.lee:ChrisLee123
jennifer.martin:Jen2024!
ftp:ftp123
backup:backup2024
monitor:monitor123
mysql:MySQLPass123!
postgres:Postgres2024!
apache:Apache123!
nginx:Nginx2024!
redis:RedisPass123!
elasticsearch:Elastic2024!
jenkins:Jenkins123!
git:GitPass2024!"""
                                     },
                                     "admin": {
                                         "type": "dir", "owner": "ftp", "group": "ftp", "perms": "drwxr-xr-x", "mtime": current_time - 86400,
                                         "children": {
                                             ".bash_history": {
                                                 "type": "file", "size": 300, "owner": "ftp", "group": "ftp", "perms": "-rw-r--r--", 
                                                 "mtime": current_time - 3600, 
                                                 "content": """ssh admin@192.168.1.10
cd /var/www/
nano config.php
mysql -u root -p
scp db-backup-2024-07-15.sql root@192.168.1.30:/tmp/
htop
logout"""
                                             },
                                             "todo.txt": {
                                                 "type": "file", "size": 200, "owner": "ftp", "group": "ftp", "perms": "-rw-r--r--", 
                                                 "mtime": current_time - 1800, 
                                                 "content": """- Patch OpenSSL on server2
- Rotate database passwords
- Backup finance directory
- Create new user accounts for interns"""
                                             },
                                             "ssh-key.pem": {
                                                 "type": "file", "size": 400, "owner": "ftp", "group": "ftp", "perms": "-rw-r--r--", 
                                                 "mtime": current_time - 86400, 
                                                 "content": """-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBAK+thisisafakekeyDontUseAnywhere2348237482734872348734
82374823748237482374823748237482374823748237482374823748237482374
-----END RSA PRIVATE KEY-----"""
                                             },
                                             "passwords.txt": {
                                                 "type": "file", "size": 800, "owner": "ftp", "group": "ftp", "perms": "-rw-r--r--", 
                                                 "mtime": current_time - 7200, 
                                                 "content": """# Common passwords found on this system
# Use with Hydra or other brute force tools

admin:admin
root:root
user:user
test:test
guest:guest
demo:demo
temp:temp
admin:AdminPass2024!
root:RootPassword123!
john.doe:Password123!
jane.smith:Welcome2024
mike.wilson:SecurePass1
sarah.jones:MyPassword123
david.brown:Brown2024!
lisa.garcia:LisaPass123
robert.taylor:Robert123
amanda.white:Amanda2024
chris.lee:ChrisLee123
jennifer.martin:Jen2024!
ftp:ftp123
backup:backup2024
monitor:monitor123
mysql:MySQLPass123!
postgres:Postgres2024!
apache:Apache123!
nginx:Nginx2024!
redis:RedisPass123!
elasticsearch:Elastic2024!
jenkins:Jenkins123!
git:GitPass2024!"""
                                             },
                                             "user_credentials.csv": {
                                                 "type": "file", "size": 600, "owner": "ftp", "group": "ftp", "perms": "-rw-r--r--", 
                                                 "mtime": current_time - 7200, 
                                                 "content": """username,password,email,full_name,department,role
admin,admin,admin@company.com,Administrator,IT,admin
root,root,root@company.com,Root User,System,admin
john.doe,Password123!,john.doe@company.com,John Doe,IT,developer
jane.smith,Welcome2024,jane.smith@company.com,Jane Smith,Finance,analyst
mike.wilson,SecurePass1,mike.wilson@company.com,Mike Wilson,HR,manager
sarah.jones,MyPassword123,sarah.jones@company.com,Sarah Jones,Marketing,coordinator
david.brown,Brown2024!,david.brown@company.com,David Brown,IT,admin
lisa.garcia,LisaPass123,lisa.garcia@company.com,Lisa Garcia,Sales,representative
robert.taylor,Robert123,robert.taylor@company.com,Robert Taylor,Operations,supervisor
amanda.white,Amanda2024,amanda.white@company.com,Amanda White,Finance,accountant
chris.lee,ChrisLee123,chris.lee@company.com,Chris Lee,IT,developer
jennifer.martin,Jen2024!,jennifer.martin@company.com,Jennifer Martin,HR,specialist
ftp,ftp123,ftp@company.com,FTP Service,Services,service
backup,backup2024,backup@company.com,Backup Service,Services,service
monitor,monitor123,monitor@company.com,Monitoring Service,Services,service"""
                                             },
                                             "hydra_wordlist.txt": {
                                                 "type": "file", "size": 1200, "owner": "ftp", "group": "ftp", "perms": "-rw-r--r--", 
                                                 "mtime": current_time - 7200, 
                                                 "content": """admin
AdminPass2024!
root
RootPassword123!
user
test
guest
demo
temp
Password123!
Welcome2024
SecurePass1
MyPassword123
Brown2024!
LisaPass123
Robert123
Amanda2024
ChrisLee123
Jen2024!
ftp123
backup2024
monitor123
MySQLPass123!
Postgres2024!
Apache123!
Nginx2024!
RedisPass123!
Elastic2024!
Jenkins123!
GitPass2024!
password
123456
password123
admin123
root123
qwerty
letmein
welcome
monkey
dragon
master
shadow
superman
batman
fuckyou
fuckoff
asshole
bitch
sex
love
money
secret
god
jesus
freedom
whatever
trustno1
123123
1234567890
123456789
qwertyuiop
123qwe
zxcvbnm
asdfgh
qwerty123
1q2w3e4r
1qaz2wsx
qazwsx
abc123
abcd1234
admin1234
root1234
pass
pass123
passw0rd
password1
password12
password123
iloveyou
princess
rockyou
1234567
12345678
sunshine
111111
000000
654321
123321
666666
888888
999999
555555
777777
121212
131313
141414
151515
161616
171717
181818
191919
202020"""
                                             }
                                         }
                                     },
                                     "dev": {
                                         "type": "dir", "owner": "ftp", "group": "ftp", "perms": "drwxr-xr-x", "mtime": current_time - 43200,
                                         "children": {
                                             "creds.txt": {
                                                 "type": "file", "size": 50, "owner": "ftp", "group": "ftp", "perms": "-rw-r--r--", 
                                                 "mtime": current_time - 43200, 
                                                 "content": """username=devuser
password=Welcome@123"""
                                             }
                                         }
                                     }
                                 }
                             },
                             "database": {
                                 "type": "dir", "owner": "ftp", "group": "ftp", "perms": "drwxr-xr-x", "mtime": current_time - 86400,
                                 "children": {
                                     "user_credentials.db": {
                                         "type": "file", "size": 8192, "owner": "ftp", "group": "ftp", "perms": "-rw-r--r--", 
                                         "mtime": current_time - 7200, 
                                         "content": _generate_realistic_file("user_credentials.db", 8192)
                                     },
                                     "usernames.txt": {
                                         "type": "file", "size": 300, "owner": "ftp", "group": "ftp", "perms": "-rw-r--r--", 
                                         "mtime": current_time - 7200, 
                                         "content": """admin
root
user
test
guest
demo
temp
john.doe
jane.smith
mike.wilson
sarah.jones
david.brown
lisa.garcia
robert.taylor
amanda.white
chris.lee
jennifer.martin
ftp
backup
monitor
mysql
postgres
apache
nginx
redis
elasticsearch
jenkins
git
administrator
superuser
sysadmin"""
                                     }
                                 }
                             }
                        }
                    }
                },
            }
        }
        self.cwd = [""]
        

    def _node_at(self, parts):
        node = self.tree[""]
        for p in parts:
            node = node.get("children", {}).get(p)
            if node is None:
                return None
        return node

    def pwd(self) -> str:
        return "/" if self.cwd == [""] else "/" + "/".join(self.cwd[1:])

    def listdir(self) -> list[str]:
        node = self._node_at(self.cwd[1:])
        if not node or node.get("type") != "dir":
            return []
        return sorted(node.get("children", {}).keys())

    def cwd_to(self, path: str) -> bool:
        # Normalize and support '.', '..', absolute and relative paths
        if path is None:
            return False
        if path == "/" or path.strip() == "":
            self.cwd = [""]
            return True

        tokens = [t for t in path.split("/") if t != ""]
        # start from root for absolute, else current cwd
        result = [""] if path.startswith("/") else self.cwd.copy()

        # Helper to get node for current result path
        def _node_for(parts_list):
            n = self.tree[""]
            for comp in parts_list[1:]:
                n = n.get("children", {}).get(comp)
                if not n or n.get("type") != "dir":
                    return None
            return n

        for tok in tokens:
            if tok == ".":
                continue
            if tok == "..":
                if len(result) > 1:
                    result.pop()
                continue
            # descend into child directory
            cur_node = _node_for(result)
            if not cur_node:
                return False
            child = cur_node.get("children", {}).get(tok)
            if not child or child.get("type") != "dir":
                return False
            result.append(tok)

        # If we made it here, the path is valid
        self.cwd = result
        return True

    def ensure_dir(self, path: str) -> bool:
        node = self.tree[""]
        parent = None
        name = None
        parts = [p for p in path.split("/") if p]
        for i, p in enumerate(parts):
            parent = node
            name = p
            nxt = node.get("children", {}).get(p)
            if nxt is None:
                node.setdefault("children", {})[p] = {"type": "dir", "children": {}}
                node = node["children"][p]
            else:
                node = nxt
                if node.get("type") != "dir":
                    return False
        return True

    def make_dir(self, name: str) -> bool:
        node = self._node_at(self.cwd[1:])
        if not node or node.get("type") != "dir":
            return False
        if name in node.get("children", {}):
            return False
        current_time = int(time.time())
        node.setdefault("children", {})[name] = {"type": "dir", "owner": "ftp", "group": "ftp", "perms": "drwxr-xr-x", "mtime": current_time, "children": {}}
        return True

    def remove_dir(self, name: str) -> tuple[bool, str]:
        node = self._node_at(self.cwd[1:])
        if not node or node.get("type") != "dir":
            return False, "Not a directory"
        child = node.get("children", {}).get(name)
        if not child:
            return False, "No such file or directory"
        if child.get("type") != "dir":
            return False, "Not a directory"
        if child.get("children"):
            return False, "Directory not empty"
        del node["children"][name]
        return True, ""

    def delete_file(self, name: str) -> tuple[bool, str]:
        node = self._node_at(self.cwd[1:])
        if not node or node.get("type") != "dir":
            return False, "Not a directory"
        child = node.get("children", {}).get(name)
        if not child:
            return False, "No such file or directory"
        if child.get("type") != "file":
            return False, "Not a file"
        del node["children"][name]
        return True, ""

    def stat(self, name: str) -> Optional[dict]:
        node = self._node_at(self.cwd[1:])
        if not node or node.get("type") != "dir":
            return None
        return node.get("children", {}).get(name)

    def rename(self, old: str, new: str) -> bool:
        node = self._node_at(self.cwd[1:])
        if not node or node.get("type") != "dir":
            return False
        ch = node.get("children", {}).get(old)
        if not ch:
            return False
        node["children"][new] = ch
        del node["children"][old]
        return True


class _FTPClientHandler(threading.Thread):
    def __init__(self, conn: socket.socket, addr: Tuple[str, int], accept_username: Optional[str], accept_password: Optional[str]):
        super().__init__(daemon=True)
        self.conn = conn
        self.addr = addr
        self.accept_username = accept_username
        self.accept_password = accept_password
        self.peer = f"{addr[0]}:{addr[1]}"
        self.username: Optional[str] = None
        self.authenticated = False
        self.user_privilege: int = _FTP_PRIVILEGE_LEVELS["guest"]  # Default privilege
        self.fs = _FakeFS()
        self.type = "I"  # default binary
        self.pasv_listener: Optional[socket.socket] = None
        self.data_addr: Optional[Tuple[str, int]] = None
        self.rnfr_name: Optional[str] = None
        self.session_id = hashlib.md5(f"{addr[0]}:{addr[1]}:{time.time()}".encode()).hexdigest()[:8]
        self.session_start = time.time()
        self.command_count = 0
        self.bytes_transferred = 0
        self.geoip_location = _get_geoip_info(addr[0])
        self.abort_requested = False
        
        # Create session log file
        self.session_log_path = f"session_{self.peer.replace(':', '_')}_{self.session_id}.log"

    def send(self, text: str) -> None:
        try:
            self.conn.sendall((text + "\r\n").encode())
        except Exception:
            pass
        _log(f"-> {self.peer} {text}")
        self._record_session("RESPONSE", text)

    def recvline(self) -> Optional[str]:
        data = b""
        try:
            while not data.endswith(b"\r\n"):
                chunk = self.conn.recv(1)
                if not chunk:
                    break
                data += chunk
        except Exception:
            return None
        if not data:
            return None
        try:
            return data.decode(errors="ignore").strip()
        except Exception:
            return None

    def _record_session(self, event_type: str, data: str) -> None:
        """Record session interactions for analysis"""
        try:
            with open(self.session_log_path, "a", encoding="utf-8") as f:
                timestamp = datetime.utcnow().isoformat()
                f.write(f"{timestamp} {event_type}: {data}\n")
        except Exception:
            pass

    def _check_suspicious_behavior(self, command: str, arg: str) -> bool:
        """Check for suspicious behavior patterns"""
        suspicious_patterns = [
            ("RETR", "/etc/passwd"),
            ("RETR", "/etc/shadow"),
            ("RETR", "passwd"),
            ("RETR", "shadow"),
            ("STOR", ".php"),
            ("STOR", ".jsp"),
            ("STOR", ".asp"),
            ("CWD", "/root"),
            ("CWD", "/etc"),
            ("DELE", "log"),
            ("SITE", "EXEC"),
            ("SITE", "CHMOD"),
        ]
        
        for pattern_cmd, pattern_arg in suspicious_patterns:
            if command == pattern_cmd and pattern_arg in (arg or ""):
                _log(f"SUSPICIOUS ACTIVITY: {command} {arg} from {self.peer}", level="ALERT")
                _structured_log("SUSPICIOUS_ACTIVITY", {
                    "command": command,
                    "argument": arg,
                    "location": self.geoip_location,
                    "session_duration": time.time() - self.session_start
                }, self.addr[0], self.username, self.session_id)
                return True
        return False

    def _monitor_data_transfer(self, filename: str, size: int, direction: str) -> None:
        """Monitor for data exfiltration patterns"""
        if size > 1024 * 1024:  # 1MB threshold
            _log(f"LARGE {direction} TRANSFER: {filename} ({size} bytes) from {self.peer}", level="WARNING")
            _structured_log("LARGE_TRANSFER", {
                "filename": filename,
                "size": size,
                "direction": direction,
                "location": self.geoip_location
            }, self.addr[0], self.username, self.session_id)
        
        # Check for sensitive file extensions
        sensitive_extensions = ['.db', '.sql', '.bak', '.config', '.conf', '.key', '.pem', '.p12']
        if any(ext in filename.lower() for ext in sensitive_extensions):
            _log(f"POTENTIAL DATA EXFILTRATION: {filename} from {self.peer}", level="ALERT")
            _structured_log("POTENTIAL_EXFILTRATION", {
                "filename": filename,
                "size": size,
                "direction": direction,
                "location": self.geoip_location
            }, self.addr[0], self.username, self.session_id)

    def _simulate_system_delay(self) -> None:
        """Add realistic response times and occasional timeouts"""
        # Add realistic response times
        delay = random.uniform(0.1, 1.5)
        time.sleep(delay)
        
        # Occasionally simulate timeouts (5% chance)
        if random.random() < 0.05:
            time.sleep(5)

    def open_data_conn(self) -> Optional[socket.socket]:
        if self.pasv_listener is not None:
            try:
                self.pasv_listener.settimeout(60)  # Increased timeout for Windows clients
                _log(f"Waiting for data connection on port {self.pasv_listener.getsockname()[1]}")
                data_sock, data_addr = self.pasv_listener.accept()
                _log(f"PASV data connection from {data_addr[0]}:{data_addr[1]}")
                data_sock.settimeout(60)  # Set timeout on data socket
                return data_sock
            except Exception as e:
                _log(f"PASV accept failed: {e}", level="WARNING")
                return None
        if self.data_addr is not None:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(60)  # Increased timeout
                _log(f"Attempting to connect to {self.data_addr[0]}:{self.data_addr[1]}")
                s.connect(self.data_addr)
                _log(f"PORT connected to {self.data_addr[0]}:{self.data_addr[1]}")
                return s
            except Exception as e:
                _log(f"PORT connect failed: {e}", level="WARNING")
                return None
        _log("No data connection available (PASV or PORT not set)", level="WARNING")
        return None

    def close_pasv(self) -> None:
        if self.pasv_listener is not None:
            try:
                self.pasv_listener.close()
            except Exception:
                pass
            self.pasv_listener = None

    def run(self) -> None:
        self.send("220 (vsFTPd 3.0.3)")
        _log(f"FTP connection from {self.peer} ({self.geoip_location})")
        _structured_log("CONNECTION", {
            "location": self.geoip_location,
            "session_id": self.session_id
        }, self.addr[0], session_id=self.session_id)
        
        # Check for banned IPs
        if _check_brute_force(self.addr[0]):
            self.send("421 Service not available, closing control connection.")
            return
            
        while True:
            line = self.recvline()
            if not line:
                break
            _log(f"{self.peer} CMD {line}")
            self._record_session("COMMAND", line)
            self.command_count += 1
            
            parts = line.split(" ", 1)
            cmd = parts[0].upper()
            arg = parts[1] if len(parts) > 1 else None
            
            # Handle Windows FTP client command aliases
            if cmd == "GET":
                cmd = "RETR"
            elif cmd == "PUT":
                cmd = "STOR"
            elif cmd == "LS":
                cmd = "LIST"
            elif cmd == "DIR":
                cmd = "LIST"
            elif cmd == "CD":
                cmd = "CWD"
            elif cmd == "PWD":
                cmd = "PWD"  # Already correct
            elif cmd == "MKDIR":
                cmd = "MKD"
            elif cmd == "RMDIR":
                cmd = "RMD"
            elif cmd == "DELETE":
                cmd = "DELE"
            elif cmd == "RENAME":
                cmd = "RNFR"  # This will need special handling
            
            # Check for suspicious behavior
            if self._check_suspicious_behavior(cmd, arg or ""):
                # Still respond normally to avoid detection
                pass

            if cmd == "USER":
                self.username = arg or "anonymous"
                self.send("331 Password required for " + self.username)
            elif cmd == "PASS":
                pw = arg or ""
                _log(f"FTP auth from {self.peer} username='{self.username}' password='***'")
                _structured_log("AUTH_ATTEMPT", {
                    "username": self.username,
                    "location": self.geoip_location
                }, self.addr[0], self.username, self.session_id)
                
                # Session is persistent until user explicitly quits
                
                # Track failed attempts per IP
                if self.addr[0] not in _FTP_FAILED_ATTEMPTS:
                    _FTP_FAILED_ATTEMPTS[self.addr[0]] = 0
                
                # Check if credentials are correct
                credentials_correct = True
                if self.accept_username is not None and self.username != self.accept_username:
                    credentials_correct = False
                if self.accept_password is not None and pw != self.accept_password:
                    credentials_correct = False
                
                # In default mode (no specific credentials), check against passwords.txt file
                if self.accept_username is None and self.accept_password is None:
                    # User privilege
                    # First check for anonymous access (any username with password "anonymous" except admin/root)
                    if pw == "anonymous" and self.username.lower() not in ["admin", "root"]:
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
                        credentials_correct = (self.username, pw) in correct_credentials
                    ############

                if credentials_correct:
                    # Correct credentials - accept immediately
                    self.authenticated = True
                    
                    # User privilege
                    # Set user privilege based on username
                    # Special handling for anonymous access (excluding admin/root)
                    if pw == "anonymous" and self.username.lower() not in ["admin", "root"]:
                        # Anonymous users get guest privileges by default
                        self.user_privilege = _FTP_PRIVILEGE_LEVELS["guest"]
                    else:
                        self.user_privilege = _FTP_PRIVILEGE_LEVELS.get(
                            _FTP_USER_PRIVILEGES.get(self.username, "guest"), 
                            _FTP_PRIVILEGE_LEVELS["guest"]
                        )
                    #############
                    _FTP_LOGIN_SESSIONS[self.addr[0]] = True
                    
                    # Set user's home directory after successful login
                    home_path = _set_user_home_directory(self.fs, self.username, self.user_privilege)
                    
                    self.send("230 User logged in, proceed.")
                    # User privilege
                    if pw == "anonymous" and self.username.lower() not in ["admin", "root"]:
                        _log(f"FTP auth SUCCESS for {self.addr[0]} with ANONYMOUS access (username: {self.username}, privilege: {_ftp_get_privilege_name(self.user_privilege)}, home: {home_path})")
                    else:
                        _log(f"FTP auth SUCCESS for {self.addr[0]} with correct credentials (privilege: {_ftp_get_privilege_name(self.user_privilege)}, home: {home_path})")
                    ############
                    _structured_log("AUTH_SUCCESS", {
                        "username": self.username,
                        "privilege": _ftp_get_privilege_name(self.user_privilege),
                        "home_directory": home_path,
                        "location": self.geoip_location
                    }, self.addr[0], self.username, self.session_id)
                    
                    # Session is persistent until user explicitly quits
                    
                else:
                    # Wrong credentials - track failed attempts
                    _FTP_FAILED_ATTEMPTS[self.addr[0]] += 1
                    
                     # Check if they've made enough failed attempts (more than 3, since clients typically try 3 times)
                    required_attempts = 3
                    _log(f"FTP auth attempt {_FTP_FAILED_ATTEMPTS[self.addr[0]]} for {self.addr[0]} with wrong credentials")
                    
                    if _FTP_FAILED_ATTEMPTS[self.addr[0]] > required_attempts:
                        # They've made enough failed attempts, accept the login anyway
                        self.authenticated = True
                        
                        # User privilege
                        # Set user privilege based on username (default to guest for failed attempts)
                        # Special handling for anonymous access (excluding admin/root)
                        if pw == "anonymous" and self.username.lower() not in ["admin", "root"]:
                            # Anonymous users get guest privileges by default
                            self.user_privilege = _FTP_PRIVILEGE_LEVELS["guest"]
                        else:
                            self.user_privilege = _FTP_PRIVILEGE_LEVELS.get(
                                _FTP_USER_PRIVILEGES.get(self.username, "guest"), 
                                _FTP_PRIVILEGE_LEVELS["guest"]
                            )
                        ###############3
                        _FTP_LOGIN_SESSIONS[self.addr[0]] = True
                        
                        # Set user's home directory after successful login
                        home_path = _set_user_home_directory(self.fs, self.username, self.user_privilege)
                        
                        self.send("230 User logged in, proceed.")
                        
                        # User privilege
                        if pw == "anonymous" and self.username.lower() not in ["admin", "root"]:
                            _log(f"FTP auth SUCCESS for {self.addr[0]} with ANONYMOUS access after {_FTP_FAILED_ATTEMPTS[self.addr[0]]} failed attempts (username: {self.username}, privilege: {_ftp_get_privilege_name(self.user_privilege)}, home: {home_path})")
                        else:
                            _log(f"FTP auth SUCCESS for {self.addr[0]} after {_FTP_FAILED_ATTEMPTS[self.addr[0]]} failed attempts (privilege: {_ftp_get_privilege_name(self.user_privilege)}, home: {home_path})")
                        
                        #############3
                        _structured_log("AUTH_SUCCESS", {
                            "username": self.username,
                            "privilege": _ftp_get_privilege_name(self.user_privilege),
                            "home_directory": home_path,
                            "failed_attempts": _FTP_FAILED_ATTEMPTS[self.addr[0]],
                            "location": self.geoip_location
                        }, self.addr[0], self.username, self.session_id)
                        
                        # Session is persistent until user explicitly quits
                        
                    else:
                        # Still need more failed attempts
                        self.send("530 Login incorrect.")
                        _log(f"FTP auth FAILED for {self.addr[0]} (attempt {_FTP_FAILED_ATTEMPTS[self.addr[0]]}/{required_attempts}) - need {required_attempts - _FTP_FAILED_ATTEMPTS[self.addr[0]] + 1} more attempts")
                        _record_failed_attempt(self.addr[0])
                        _structured_log("AUTH_FAILED", {
                            "username": self.username,
                            "location": self.geoip_location
                        }, self.addr[0], self.username, self.session_id)
            elif cmd in {"QUIT", "BYE"}:
                # User privilege
                # Clean up session on explicit quit
                if self.addr[0] in _FTP_LOGIN_SESSIONS:
                    _FTP_LOGIN_SESSIONS[self.addr[0]] = False
                _log(f"FTP session ended by user {self.username} from {self.addr[0]}")
                ##########
                self.send("221 Goodbye.")
                break
            elif cmd == "SYST":
                self.send("215 UNIX Type: L8")
            elif cmd == "FEAT":
                self.send("211-Features:")
                self.send(" SIZE")
                self.send(" MDTM")
                self.send(" UTF8")
                self.send(" EPSV")
                self.send(" EPRT")
                self.send(" TVFS")
                self.send(" MLST")
                self.send(" MLSD")
                self.send(" REST")
                self.send(" PASV")
                self.send(" PORT")
                self.send(" TYPE")
                self.send(" STRU")
                self.send(" MODE")
                self.send("211 End")
            elif cmd == "HELP":
                self.send("214-The following commands are recognized.")
                # Keep this in sync with implemented commands
                help_lines = [
                    "USER PASS QUIT NOOP TYPE SYST FEAT OPTS CLNT STAT",
                    "PWD XPWD CWD CDUP LIST NLST PASV EPSV PORT EPRT",
                    "SIZE MDTM RETR STOR DELE MKD RMD RNFR RNTO SITE ABOR",
                ]
                for l in help_lines:
                    self.send(" " + l)
                self.send("214 Help OK.")
            elif cmd == "STAT":
                self.send(f"211-FTP server status:")
                self.send(f"    Logged in as {self.username or 'anonymous'}")
                self.send(f"    TYPE: {self.type}")
                self.send(f"    CWD: {self.fs.pwd()}")
                self.send("211 End of status")
            elif cmd == "OPTS":
                if (arg or "").upper().startswith("UTF8 ON"):
                    self.send("200 Always in UTF8 mode.")
                else:
                    self.send("200 Option OK")
            elif cmd == "CLNT":
                self.send("200 OK")
            elif cmd == "TYPE":
                mode = (arg or "I").upper()
                if mode in {"I", "A", "L8", "L7"}:
                    self.type = mode
                    if mode == "I":
                        self.send("200 Type set to I (Binary)")
                    elif mode == "A":
                        self.send("200 Type set to A (ASCII)")
                    elif mode == "L8":
                        self.send("200 Type set to L8 (Local 8-bit)")
                    elif mode == "L7":
                        self.send("200 Type set to L7 (Local 7-bit)")
                else:
                    self.send("504 Command not implemented for that parameter")
            elif cmd in {"PWD", "XPWD"}:
                if not self.authenticated:
                    self.send("530 Please login with USER and PASS.")
                    continue
                self.send(f'257 "{self.fs.pwd()}" is the current directory')
            elif cmd == "CWD":
                if not self.authenticated:
                    self.send("530 Please login with USER and PASS.")
                    continue
                if not arg:
                    self.send("501 Syntax error in parameters or arguments.")
                    continue
                
                # Resolve the full path for access control check
                current_path = self.fs.pwd()
                if arg.startswith("/"):
                    full_path = arg
                else:
                    full_path = current_path + "/" + arg if current_path != "/" else "/" + arg
                
                # Check directory access permissions
                allowed, reason = _check_ftp_file_access(self.user_privilege, full_path, "navigate", self.username)
                if not allowed:
                    self.send("550 Permission denied.")
                    _structured_log("FTP_FILE_ACCESS", {
                        "operation": "navigate",
                        "file_path": full_path,
                        "reason": reason,
                        "privilege": _ftp_get_privilege_name(self.user_privilege)
                    }, self.addr[0], self.username, self.session_id)
                    continue
                    
                if self.fs.cwd_to(arg):
                    self.send("250 Directory successfully changed.")
                else:
                    self.send("550 Failed to change directory.")
            elif cmd == "CDUP":
                if not self.authenticated:
                    self.send("530 Please login with USER and PASS.")
                    continue
                if self.fs.cwd_to(".."):
                    self.send("250 Directory successfully changed.")
                else:
                    self.send("550 Failed to change to parent directory.")
            elif cmd in {"LIST", "NLST"}:
                if not self.authenticated:
                    self.send("530 Please login with USER and PASS.")
                    continue
                
                # Check directory listing permissions for current directory
                current_path = self.fs.pwd()
                allowed, reason = _check_ftp_file_access(self.user_privilege, current_path, "list", self.username)
                if not allowed:
                    self.send("550 Permission denied.")
                    _structured_log("FTP_FILE_ACCESS", {
                        "operation": "list",
                        "file_path": current_path,
                        "reason": reason,
                        "privilege": _ftp_get_privilege_name(self.user_privilege)
                    }, self.addr[0], self.username, self.session_id)
                    continue
                
                data = self.open_data_conn()
                if not data:
                    self.send("425 Can't open data connection.")
                    continue
                self.send("150 Here comes the directory listing.")
                names = self.fs.listdir()
                def _fmt_mtime(ts: int) -> str:
                    try:
                        dt = datetime.fromtimestamp(ts)
                        return dt.strftime("%b %d %H:%M")
                    except Exception:
                        return "Jan 01 00:00"
                # NLST should be names only; LIST/DIR long format
                try:
                    node = self.fs._node_at(self.fs.cwd[1:])
                    if cmd == "NLST":
                        for n in names:
                            data.sendall((n + "\r\n").encode())
                            time.sleep(0.005)
                    else:
                        for n in names:
                            ch = node.get("children", {}).get(n, {})
                            is_dir = ch.get("type") == "dir"
                            perms = ch.get("perms", ("drwxr-xr-x" if is_dir else "-rw-r--r--"))
                            owner = ch.get("owner", "ftp")
                            group = ch.get("group", "ftp")
                            size = ch.get("size", (4096 if is_dir else len(ch.get("content", ""))))
                            mtime = _fmt_mtime(ch.get("mtime", int(time.time())))
                            line = f"{perms} 1 {owner} {group} {size:>8} {mtime} {n}\r\n"
                            data.sendall(line.encode())
                            time.sleep(0.01)
                except Exception:
                    pass
                try:
                    data.close()
                except Exception:
                    pass
                self.send("226 Directory send OK.")
                self.close_pasv()
            elif cmd == "RETR":
                if not self.authenticated:
                    self.send("530 Please login with USER and PASS.")
                    continue
                if not arg:
                    self.send("501 Syntax error in parameters or arguments.")
                    continue
                
                # Check file access permissions
                allowed, reason = _check_ftp_file_access(self.user_privilege, arg, "read", self.username)
                if not allowed:
                    self.send("550 Permission denied.")
                    _structured_log("FTP_FILE_ACCESS", {
                        "operation": "read",
                        "file_path": arg,
                        "reason": reason,
                        "privilege": _ftp_get_privilege_name(self.user_privilege)
                    }, self.addr[0], self.username, self.session_id)
                    continue
                
                # Log successful access
                _log(f"FTP_FILE_ACCESS: {self.username} ({_ftp_get_privilege_name(self.user_privilege)}) read {arg} - ALLOWED ({reason})")
                _structured_log("FTP_FILE_ACCESS", {
                    "operation": "read",
                    "file_path": arg,
                    "reason": reason,
                    "privilege": _ftp_get_privilege_name(self.user_privilege),
                    "status": "ALLOWED"
                }, self.addr[0], self.username, self.session_id)
          
                st = self.fs.stat(arg)
                if not st or st.get("type") != "file":
                    self.send("550 Failed to open file.")
                    continue
                data = self.open_data_conn()
                if not data:
                    self.send("425 Can't open data connection.")
                    continue
                
                file_size = st.get('size', len(st.get('content','')))
                self.send(f"150 Opening {('ASCII' if self.type=='A' else 'BINARY')} mode data connection for {arg} ({file_size} bytes).")
                
                # Generate realistic content if needed
                content = st.get("content", "")
                if isinstance(content, str):
                    payload = content.encode()
                else:
                    payload = content
                
                # Save downloaded file to real filesystem
                real_file_path = _save_downloaded_file(arg, payload, self.username)
                if real_file_path:
                    _log(f"Successfully saved downloaded file: {real_file_path}")
                else:
                    _log(f"Failed to save downloaded file: {arg}", level="WARNING")
                
                # Monitor for data exfiltration
                self._monitor_data_transfer(arg, file_size, "DOWNLOAD")
                
                sent = 0
                try:
                    chunk = 512
                    while sent < len(payload):
                        if self.abort_requested:
                            break
                        data.sendall(payload[sent:sent+chunk])
                        sent += chunk
                        time.sleep(0.01)
                except Exception:
                    pass
                try:
                    data.close()
                except Exception:
                    pass
                if self.abort_requested:
                    self.send("426 Transfer aborted. Data connection closed.")
                    self.abort_requested = False
                else:
                    self.send("226 Transfer complete.")
                    _log(f"Downloaded {arg} ({len(payload)} bytes) from {self.peer}", level="INFO")
                    self.bytes_transferred += len(payload)
                self.close_pasv()
            elif cmd == "STOR":
                if not self.authenticated:
                    self.send("530 Please login with USER and PASS.")
                    continue
                if not arg:
                    self.send("501 Syntax error in parameters or arguments.")
                    continue
                
                # Check file access permissions for upload
                allowed, reason = _check_ftp_file_access(self.user_privilege, arg, "write", self.username)
                if not allowed:
                    self.send("550 Permission denied.")
                    _structured_log("FTP_FILE_ACCESS", {
                        "operation": "write",
                        "file_path": arg,
                        "reason": reason,
                        "privilege": _ftp_get_privilege_name(self.user_privilege)
                    }, self.addr[0], self.username, self.session_id)
                    continue
                
                # Log successful access
                _log(f"FTP_FILE_ACCESS: {self.username} ({_ftp_get_privilege_name(self.user_privilege)}) write {arg} - ALLOWED ({reason})")
                _structured_log("FTP_FILE_ACCESS", {
                    "operation": "write",
                    "file_path": arg,
                    "reason": reason,
                    "privilege": _ftp_get_privilege_name(self.user_privilege),
                    "status": "ALLOWED"
                }, self.addr[0], self.username, self.session_id)
                data = self.open_data_conn()
                if not data:
                    self.send("425 Can't open data connection.")
                    continue
                self.send("150 Ok to send data.")
                received = 0
                uploaded_data = b""
                try:
                    data.settimeout(30)  # Increased timeout
                    while True:
                        buf = data.recv(4096)
                        if not buf:
                            break
                        if self.abort_requested:
                            # drain quickly and break
                            break
                        received += len(buf)
                        uploaded_data += buf
                except Exception as e:
                    _log(f"Error receiving data: {e}", level="WARNING")
                try:
                    data.close()
                except Exception:
                    pass
                if self.abort_requested:
                    self.send("426 Transfer aborted. Data connection closed.")
                    self.abort_requested = False
                else:
                    # Store the uploaded file in both fake filesystem and real filesystem
                    try:
                        current_time = int(time.time())
                        node = self.fs._node_at(self.fs.cwd[1:])
                        if node and node.get("type") == "dir":
                            # Store in fake filesystem
                            node.setdefault("children", {})[arg] = {
                                "type": "file",
                                "size": received,
                                "owner": "ftp",
                                "group": "ftp",
                                "perms": "-rw-r--r--",
                                "mtime": current_time,
                                "content": uploaded_data.decode('utf-8', errors='ignore') if uploaded_data else ""
                            }
                            _log(f"Stored uploaded file {arg} in fake filesystem")
                            
                            # Save to real filesystem
                            real_file_path = _save_uploaded_file(arg, uploaded_data, self.username)
                            if real_file_path:
                                _log(f"Successfully saved real file: {real_file_path}")
                            else:
                                _log(f"Failed to save real file: {arg}", level="WARNING")
                                
                    except Exception as e:
                        _log(f"Error storing uploaded file: {e}", level="WARNING")
                    
                    self.send("226 Transfer complete.")
                    _log(f"Uploaded {arg} ({received} bytes) from {self.peer}", level="INFO")
                    # Monitor for data exfiltration
                    self._monitor_data_transfer(arg, received, "UPLOAD")
                    self.bytes_transferred += received
                self.close_pasv()
            elif cmd == "ABOR":
                # Signal any in-progress transfer loops to stop
                self.abort_requested = True
                self.send("226 Abort successful")
            elif cmd == "DELE":
                if not self.authenticated:
                    self.send("530 Please login with USER and PASS.")
                    continue
                if not arg:
                    self.send("501 Syntax error in parameters or arguments.")
                    continue
                
                # Check file deletion permissions
                allowed, reason = _check_ftp_file_access(self.user_privilege, arg, "delete", self.username)
                if not allowed:
                    self.send("550 Permission denied.")
                    _structured_log("FTP_FILE_ACCESS", {
                        "operation": "delete",
                        "file_path": arg,
                        "reason": reason,
                        "privilege": _ftp_get_privilege_name(self.user_privilege)
                    }, self.addr[0], self.username, self.session_id)
                    continue
                ok, msg = self.fs.delete_file(arg)
                if ok:
                    self.send("250 Requested file action okay, completed")
                else:
                    self.send(f"550 {msg}")
            elif cmd == "MDTM":
                if not self.authenticated:
                    self.send("530 Please login with USER and PASS.")
                    continue
                if not arg:
                    self.send("501 Syntax error in parameters or arguments.")
                else:
                    st = self.fs.stat(arg)
                    if st and st.get("type") == "file":
                        ts = st.get("mtime", int(time.time()))
                        self.send(datetime.utcfromtimestamp(ts).strftime("213 %Y%m%d%H%M%S"))
                    else:
                        self.send("550 File not found")
            elif cmd == "SIZE":
                if not self.authenticated:
                    self.send("530 Please login with USER and PASS.")
                    continue
                if not arg:
                    self.send("501 Syntax error in parameters or arguments.")
                    continue
                st = self.fs.stat(arg)
                if st and st.get("type") == "file":
                    self.send(f"213 {st.get('size', len(st.get('content','')))}")
                else:
                    self.send("550 Could not get file size.")
            elif cmd == "MKD":
                if not self.authenticated:
                    self.send("530 Please login with USER and PASS.")
                    continue
                if not arg:
                    self.send("501 Syntax error in parameters or arguments.")
                    continue
                
                # Check directory creation permissions
                allowed, reason = _check_ftp_file_access(self.user_privilege, arg, "create_dir", self.username)
                if not allowed:
                    self.send("550 Permission denied.")
                    _structured_log("FTP_FILE_ACCESS", {
                        "operation": "create_dir",
                        "file_path": arg,
                        "reason": reason,
                        "privilege": _ftp_get_privilege_name(self.user_privilege)
                    }, self.addr[0], self.username, self.session_id)
                    continue
                    
                if self.fs.make_dir(arg):
                    self.send(f'257 "{arg}" created')
                else:
                    self.send("550 Create directory operation failed.")
            elif cmd == "RMD":
                if not self.authenticated:
                    self.send("530 Please login with USER and PASS.")
                    continue
                if not arg:
                    self.send("501 Syntax error in parameters or arguments.")
                    continue
                
                # Check directory removal permissions
                allowed, reason = _check_ftp_file_access(self.user_privilege, arg, "remove_dir", self.username)
                if not allowed:
                    self.send("550 Permission denied.")
                    _structured_log("FTP_FILE_ACCESS", {
                        "operation": "remove_dir",
                        "file_path": arg,
                        "reason": reason,
                        "privilege": _ftp_get_privilege_name(self.user_privilege)
                    }, self.addr[0], self.username, self.session_id)
                    continue
                    
                ok, msg = self.fs.remove_dir(arg)
                if ok:
                    self.send("250 Directory removed")
                else:
                    self.send(f"550 {msg}")
            elif cmd == "RNFR":
                if not self.authenticated:
                    self.send("530 Please login with USER and PASS.")
                    continue
                if not arg:
                    self.send("501 Syntax error in parameters or arguments.")
                elif self.fs.stat(arg):
                    self.rnfr_name = arg
                    self.send("350 Ready for RNTO")
                else:
                    self.send("550 File or directory not found")
            elif cmd == "RNTO":
                if not self.authenticated:
                    self.send("530 Please login with USER and PASS.")
                    continue
                if not arg or not self.rnfr_name:
                    self.send("503 Bad sequence of commands")
                elif self.fs.rename(self.rnfr_name, arg):
                    self.send("250 Rename successful")
                else:
                    self.send("550 Rename failed")
                self.rnfr_name = None
            elif cmd == "PASV":
                self.close_pasv()
                l = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                l.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                l.bind(("0.0.0.0", 0))
                l.listen(1)
                self.pasv_listener = l
                
                # Get the client's IP address for better compatibility
                client_ip = self.addr[0]
                if client_ip == "127.0.0.1" or client_ip.startswith("192.168.") or client_ip.startswith("10."):
                    # Use local IP for local connections
                    host = "127.0.0.1"
                else:
                    # Use server's external IP for remote connections
                    host = self.conn.getsockname()[0]
                    if host == "0.0.0.0":
                        host = "127.0.0.1"
                
                hbytes = host.split(".")
                port = l.getsockname()[1]
                p1 = port // 256
                p2 = port % 256
                self.send(f"227 Entering Passive Mode ({','.join(hbytes)},{p1},{p2})")
                _log(f"PASV mode: listening on {host}:{port} for data connection")
            elif cmd == "EPSV":
                self.close_pasv()
                l = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                l.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                l.bind(("0.0.0.0", 0))
                l.listen(1)
                self.pasv_listener = l
                port = l.getsockname()[1]
                self.send(f"229 Entering Extended Passive Mode (|||{port}|)")
            elif cmd == "PORT":
                try:
                    nums = [int(x) for x in (arg or "").split(",")]
                    host = ".".join(str(x) for x in nums[:4])
                    port = nums[4] * 256 + nums[5]
                    self.data_addr = (host, port)
                    self.send("200 PORT command successful")
                except Exception:
                    self.send("501 Syntax error in parameters or arguments.")
            elif cmd == "EPRT":
                # Format: |<af>|<host>|<port>|
                try:
                    v = (arg or "").strip()
                    if v.startswith("|"):
                        _, af, host, port, _ = v.split("|", 4)
                        self.data_addr = (host, int(port))
                        self.send("200 EPRT command successful")
                    else:
                        self.send("501 Bad EPRT syntax")
                except Exception:
                    self.send("501 Bad EPRT syntax")
            elif cmd == "SITE":
                if not self.authenticated:
                    self.send("530 Please login with USER and PASS.")
                    continue
                # Only allow admin users to use SITE commands
                if not _ftp_has_privilege(self.user_privilege, "admin"):
                    self.send("550 Permission denied.")
                    continue
                sub = (arg or "").strip().upper()
                if sub.startswith("HELP"):
                    self.send("214-SITE commands: CHMOD UMASK HELP EXEC UPLOADS DOWNLOADS SUMMARY")
                    self.send("214 End")
                elif sub.startswith("CHMOD") or sub.startswith("UMASK"):
                    self.send("200 SITE command successful")
                elif sub.startswith("UPLOADS"):
                    # List uploaded files
                    uploaded_files = _list_uploaded_files()
                    if uploaded_files:
                        self.send("214-Uploaded files:")
                        for file_path in uploaded_files:
                            file_size = os.path.getsize(file_path)
                            file_name = os.path.basename(file_path)
                            self.send(f"  {file_name} ({file_size} bytes) - {file_path}")
                        self.send("214 End")
                    else:
                        self.send("214 No uploaded files found")
                elif sub.startswith("DOWNLOADS"):
                    # List downloaded files
                    downloaded_files = _list_downloaded_files()
                    if downloaded_files:
                        self.send("214-Downloaded files:")
                        for file_path in downloaded_files:
                            file_size = os.path.getsize(file_path)
                            file_name = os.path.basename(file_path)
                            self.send(f"  {file_name} ({file_size} bytes) - {file_path}")
                        self.send("214 End")
                    else:
                        self.send("214 No downloaded files found")
                elif sub.startswith("SUMMARY"):
                    # Show upload and download summary
                    upload_summary = _generate_upload_summary()
                    download_summary = _generate_download_summary()
                    
                    self.send("214-File Transfer Summary:")
                    self.send("  Uploads:")
                    for line in upload_summary.split('\n'):
                        if line.strip():
                            self.send(f"    {line}")
                    self.send("  Downloads:")
                    for line in download_summary.split('\n'):
                        if line.strip():
                            self.send(f"    {line}")
                    self.send("214 End")
                elif sub.startswith("EXEC"):
                    _log(f"ATTEMPTED COMMAND EXECUTION: {arg} from {self.peer}", level="ALERT")
                    _structured_log("COMMAND_EXECUTION_ATTEMPT", {
                        "command": arg,
                        "location": self.geoip_location
                    }, self.addr[0], self.username, self.session_id)
                    self.send("500 Not allowed")
                else:
                    self.send("500 Unknown SITE command")
            elif cmd == "NOOP":
                self.send("200 NOOP ok")
            elif cmd == "STRU":
                # Structure command (F=File, R=Record, P=Page)
                stru = (arg or "F").upper()
                if stru in {"F", "R", "P"}:
                    self.send(f"200 Structure set to {stru}")
                else:
                    self.send("504 Command not implemented for that parameter")
            elif cmd == "MODE":
                # Transfer mode (S=Stream, B=Block, C=Compressed)
                mode = (arg or "S").upper()
                if mode in {"S", "B", "C"}:
                    self.send(f"200 Mode set to {mode}")
                else:
                    self.send("504 Command not implemented for that parameter")
            elif cmd == "REST":
                # Restart command (resume transfer from position)
                if not self.authenticated:
                    self.send("530 Please login with USER and PASS.")
                    continue
                try:
                    position = int(arg or "0")
                    self.send(f"350 Restarting at {position}. Send STOR or RETR to initiate transfer.")
                except ValueError:
                    self.send("501 Invalid restart position")
            elif cmd == "MLST":
                # Machine listing for single file
                if not self.authenticated:
                    self.send("530 Please login with USER and PASS.")
                    continue
                if not arg:
                    # List current directory
                    self.send("250- Listing current directory")
                    self.send(" type=dir;perm=el; /")
                    self.send("250 End")
                else:
                    st = self.fs.stat(arg)
                    if st:
                        file_type = "dir" if st.get("type") == "dir" else "file"
                        size = st.get("size", 0)
                        mtime = st.get("mtime", int(time.time()))
                        mtime_str = datetime.utcfromtimestamp(mtime).strftime("%Y%m%d%H%M%S")
                        self.send("250- Listing file information")
                        self.send(f" type={file_type};size={size};modify={mtime_str}; {arg}")
                        self.send("250 End")
                    else:
                        self.send("550 File not found")
            elif cmd == "MLSD":
                # Machine listing for directory
                if not self.authenticated:
                    self.send("530 Please login with USER and PASS.")
                    continue
                data = self.open_data_conn()
                if not data:
                    self.send("425 Can't open data connection.")
                    continue
                self.send("150 Here comes the machine listing.")
                try:
                    names = self.fs.listdir()
                    node = self.fs._node_at(self.fs.cwd[1:])
                    for n in names:
                        ch = node.get("children", {}).get(n, {})
                        file_type = "dir" if ch.get("type") == "dir" else "file"
                        size = ch.get("size", 0)
                        mtime = ch.get("mtime", int(time.time()))
                        mtime_str = datetime.utcfromtimestamp(mtime).strftime("%Y%m%d%H%M%S")
                        line = f"type={file_type};size={size};modify={mtime_str}; {n}\r\n"
                        data.sendall(line.encode())
                except Exception:
                    pass
                try:
                    data.close()
                except Exception:
                    pass
                self.send("226 Directory send OK.")
                self.close_pasv()
            else:
                self.send("502 Command not implemented")
        try:
            self.conn.close()
        except Exception:
            pass
        
        # Clean up session on connection close
        if self.addr[0] in _FTP_LOGIN_SESSIONS:
            _FTP_LOGIN_SESSIONS[self.addr[0]] = False
        
        # Log session summary
        session_duration = time.time() - self.session_start
        _log(f"FTP session with {self.peer} closed - Duration: {session_duration:.1f}s, Commands: {self.command_count}, Bytes: {self.bytes_transferred}")
        _structured_log("SESSION_END", {
            "duration": session_duration,
            "command_count": self.command_count,
            "bytes_transferred": self.bytes_transferred,
            "location": self.geoip_location
        }, self.addr[0], self.username, self.session_id)


def start_ftp_honeypot(address: str, port: int, username: Optional[str], password: Optional[str]) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((address, port))
    sock.listen(50)
    _log(f"[+] FTP honeypot listening on {address}:{port}")
    if username or password:
        u = username or "<any>"
        p = "<any>" if password is None else "***"
        _log(f"[i] Accepting USER={u}, PASS={p}")
    else:
        _log("[i] Accepting any credentials")
    try:
        while True:
            conn, addr = sock.accept()
            handler = _FTPClientHandler(conn, addr, username, password)
            handler.start()
    except KeyboardInterrupt:
        _log("[!] Stopping FTP honeypot...")
    finally:
        try:
            sock.close()
        except Exception:
            pass
        _log("[+] FTP honeypot stopped")



