#!/usr/bin/env python3
"""
FTP Access Control Test Script
This script demonstrates the new access control features in the FTP honeypot
"""

import socket
import time

def test_ftp_access_control():
    """Test FTP access control with different user privilege levels"""
    
    def connect_and_test(username, password, test_name):
        """Connect with specific credentials and test access control"""
        print(f"\n{'='*60}")
        print(f"🧪 Testing: {test_name}")
        print(f"👤 Username: {username}")
        print(f"🔑 Password: {password}")
        print(f"{'='*60}")
        
        try:
            # Connect to FTP honeypot
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect(('localhost', 2121))
            
            # Receive welcome message
            welcome = sock.recv(1024).decode().strip()
            print(f"📡 Welcome: {welcome}")
            
            # Login
            sock.send(f"USER {username}\r\n".encode())
            response = sock.recv(1024).decode().strip()
            print(f"👤 USER: {response}")
            
            sock.send(f"PASS {password}\r\n".encode())
            response = sock.recv(1024).decode().strip()
            print(f"🔑 PASS: {response}")
            
            if "230" in response:
                print("✅ Login successful!")
                
                # Check current directory after login (should be home directory)
                sock.send(b"PWD\r\n")
                response = sock.recv(1024).decode().strip()
                print(f"🏠 Current directory after login: {response}")
                
                # Test directory access
                test_directories = [
                    ("/", "Root directory"),
                    ("/etc", "System configuration directory"),
                    ("/var", "Variable data directory"),
                    ("/tmp", "Temporary directory"),
                    ("/ftp", "FTP directory"),
                    ("/home", "Home directory"),
                    ("/home/admin", "Admin home directory"),
                    ("/home/user", "User home directory"),
                    ("/home/test", "Test home directory"),
                    ("/home/guest", "Guest home directory"),
                    ("/ftp/users/admin", "Admin user directory")
                ]
                
                print("\n📁 Testing directory access:")
                for directory, description in test_directories:
                    sock.send(f"CWD {directory}\r\n".encode())
                    response = sock.recv(1024).decode().strip()
                    status = "✅ ALLOWED" if "250" in response else "❌ DENIED"
                    print(f"   {directory:<20} ({description:<25}) - {status}")
                    if "550" in response:
                        print(f"      Reason: {response}")
                
                # Test file access
                test_files = [
                    ("/etc/passwd", "System password file"),
                    ("/etc/shadow", "System shadow file"),
                    ("/etc/hosts", "System hosts file"),
                    ("/ftp/users/admin/passwords.txt", "Admin password file"),
                    ("/ftp/finance/Q3-report.xlsx", "Financial document"),
                    ("/ftp/database/user_credentials.db", "Database file"),
                    ("/file1.txt", "Regular file in root")
                ]
                
                print("\n📄 Testing file access:")
                for file_path, description in test_files:
                    sock.send(f"RETR {file_path}\r\n".encode())
                    response = sock.recv(1024).decode().strip()
                    status = "✅ ALLOWED" if "150" in response else "❌ DENIED"
                    print(f"   {file_path:<35} ({description:<25}) - {status}")
                    if "550" in response:
                        print(f"      Reason: {response}")
                
                # Test file upload permissions
                print("\n📤 Testing upload permissions:")
                test_uploads = [
                    ("/test_upload.txt", "Upload to root"),
                    ("/etc/test_config.txt", "Upload to system directory"),
                    ("/ftp/test_file.txt", "Upload to FTP directory"),
                    ("/home/test_home.txt", "Upload to home directory")
                ]
                
                for file_path, description in test_uploads:
                    sock.send(f"STOR {file_path}\r\n".encode())
                    response = sock.recv(1024).decode().strip()
                    status = "✅ ALLOWED" if "150" in response else "❌ DENIED"
                    print(f"   {file_path:<30} ({description:<25}) - {status}")
                    if "550" in response:
                        print(f"      Reason: {response}")
                
            else:
                print("❌ Login failed!")
            
            # Quit
            sock.send(b"QUIT\r\n")
            response = sock.recv(1024).decode().strip()
            print(f"👋 QUIT: {response}")
            
            sock.close()
            
        except Exception as e:
            print(f"❌ Connection failed: {e}")
    
    print("🍯 FTP Honeypot Access Control Test")
    print("This script tests the new access control features")
    print("Make sure the FTP honeypot is running on localhost:2121")
    
    # Test different privilege levels
    test_cases = [
        ("guest", "anonymous", "Guest User (Limited to /ftp)"),
        ("user", "user", "Regular User (/ftp and /home)"),
        ("admin", "admin", "Admin User (Most areas except root-only)"),
        ("root", "root", "Root User (Full access)")
    ]
    
    for username, password, description in test_cases:
        connect_and_test(username, password, description)
        time.sleep(1)  # Brief pause between tests
    
    print(f"\n{'='*60}")
    print("📊 Access Control Summary:")
    print("🔴 Root-only paths: /etc, /var, /tmp, /root, /bin, /sbin, etc.")
    print("🟡 Admin-only files: passwd, shadow, hosts, config, credentials, etc.")
    print("🟢 Guest access: Limited to /ftp directory")
    print("🟢 User access: /ftp and /home directories")
    print("🟢 Admin access: Most areas except root-only paths")
    print("🟢 Root access: Full system access")
    print(f"{'='*60}")

if __name__ == "__main__":
    test_ftp_access_control()
