#!/usr/bin/env python3
"""
FTP Connection Test Script
This script demonstrates how to properly connect to the FTP honeypot
"""

import socket
import time

def test_ftp_connection():
    """Test connection to the FTP honeypot"""
    try:
        # Connect to the FTP honeypot on port 2121
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect(('localhost', 2121))
        
        # Receive welcome message
        welcome = sock.recv(1024).decode().strip()
        print(f"Welcome message: {welcome}")
        
        # Send USER command
        sock.send(b"USER admin\r\n")
        response = sock.recv(1024).decode().strip()
        print(f"USER response: {response}")
        
        # Send PASS command
        sock.send(b"PASS admin\r\n")
        response = sock.recv(1024).decode().strip()
        print(f"PASS response: {response}")
        
        # Send PWD command to test if logged in
        sock.send(b"PWD\r\n")
        response = sock.recv(1024).decode().strip()
        print(f"PWD response: {response}")
        
        # Send QUIT command
        sock.send(b"QUIT\r\n")
        response = sock.recv(1024).decode().strip()
        print(f"QUIT response: {response}")
        
        sock.close()
        print("\n✅ FTP connection test successful!")
        
    except Exception as e:
        print(f"❌ Connection failed: {e}")

if __name__ == "__main__":
    print("Testing FTP honeypot connection...")
    test_ftp_connection()
