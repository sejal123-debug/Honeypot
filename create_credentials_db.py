#!/usr/bin/env python3
"""
Script to create a SQLite database with realistic usernames and passwords
for the honeypot. This database will be discoverable by attackers using tools like Hydra.
"""

import sqlite3
import hashlib
import random
import os
from datetime import datetime

def create_credentials_database():
    """Create a SQLite database with realistic user credentials"""
    
    # Remove existing database if it exists
    db_path = "user_credentials.db"
    if os.path.exists(db_path):
        os.remove(db_path)
    
    # Create new database
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT,
            full_name TEXT,
            department TEXT,
            role TEXT,
            last_login DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            is_active BOOLEAN DEFAULT 1
        )
    ''')
    
    # Create admin table (more sensitive)
    cursor.execute('''
        CREATE TABLE admin_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            access_level TEXT,
            last_login DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create system accounts table
    cursor.execute('''
        CREATE TABLE system_accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            service TEXT,
            description TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Realistic usernames and passwords
    users_data = [
        # Regular users
        ("john.doe", "Password123!", "john.doe@company.com", "John Doe", "IT", "developer"),
        ("jane.smith", "Welcome2024", "jane.smith@company.com", "Jane Smith", "Finance", "analyst"),
        ("mike.wilson", "SecurePass1", "mike.wilson@company.com", "Mike Wilson", "HR", "manager"),
        ("sarah.jones", "MyPassword123", "sarah.jones@company.com", "Sarah Jones", "Marketing", "coordinator"),
        ("david.brown", "Brown2024!", "david.brown@company.com", "David Brown", "IT", "admin"),
        ("lisa.garcia", "LisaPass123", "lisa.garcia@company.com", "Lisa Garcia", "Sales", "representative"),
        ("robert.taylor", "Robert123", "robert.taylor@company.com", "Robert Taylor", "Operations", "supervisor"),
        ("amanda.white", "Amanda2024", "amanda.white@company.com", "Amanda White", "Finance", "accountant"),
        ("chris.lee", "ChrisLee123", "chris.lee@company.com", "Chris Lee", "IT", "developer"),
        ("jennifer.martin", "Jen2024!", "jennifer.martin@company.com", "Jennifer Martin", "HR", "specialist"),
        
        # Common weak passwords
        ("admin", "admin", "admin@company.com", "Administrator", "IT", "admin"),
        ("root", "root", "root@company.com", "Root User", "System", "admin"),
        ("user", "user", "user@company.com", "Default User", "General", "user"),
        ("test", "test", "test@company.com", "Test User", "Testing", "user"),
        ("guest", "guest", "guest@company.com", "Guest User", "General", "guest"),
        ("demo", "demo", "demo@company.com", "Demo User", "Demo", "user"),
        ("temp", "temp", "temp@company.com", "Temporary User", "General", "user"),
        
        # Service accounts
        ("ftp", "ftp123", "ftp@company.com", "FTP Service", "Services", "service"),
        ("backup", "backup2024", "backup@company.com", "Backup Service", "Services", "service"),
        ("monitor", "monitor123", "monitor@company.com", "Monitoring Service", "Services", "service"),
    ]
    
    # Admin users (more sensitive)
    admin_data = [
        ("admin", "AdminPass2024!", "super_admin"),
        ("root", "RootPassword123!", "system_admin"),
        ("superuser", "SuperUser2024!", "admin"),
        ("administrator", "Admin123!", "admin"),
        ("sysadmin", "SysAdmin2024!", "system_admin"),
    ]
    
    # System accounts
    system_data = [
        ("mysql", "MySQLPass123!", "database", "MySQL database user"),
        ("postgres", "Postgres2024!", "database", "PostgreSQL database user"),
        ("apache", "Apache123!", "web", "Apache web server user"),
        ("nginx", "Nginx2024!", "web", "Nginx web server user"),
        ("redis", "RedisPass123!", "cache", "Redis cache user"),
        ("elasticsearch", "Elastic2024!", "search", "Elasticsearch user"),
        ("jenkins", "Jenkins123!", "ci_cd", "Jenkins CI/CD user"),
        ("git", "GitPass2024!", "version_control", "Git repository user"),
    ]
    
    # Insert regular users
    for username, password, email, full_name, department, role in users_data:
        password_hash = hashlib.md5(password.encode()).hexdigest()
        cursor.execute('''
            INSERT INTO users (username, password, password_hash, email, full_name, department, role, last_login)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (username, password, password_hash, email, full_name, department, role, 
              datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
    
    # Insert admin users
    for username, password, access_level in admin_data:
        password_hash = hashlib.md5(password.encode()).hexdigest()
        cursor.execute('''
            INSERT INTO admin_users (username, password, password_hash, access_level, last_login)
            VALUES (?, ?, ?, ?, ?)
        ''', (username, password, password_hash, access_level, 
              datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
    
    # Insert system accounts
    for username, password, service, description in system_data:
        password_hash = hashlib.md5(password.encode()).hexdigest()
        cursor.execute('''
            INSERT INTO system_accounts (username, password, password_hash, service, description)
            VALUES (?, ?, ?, ?, ?)
        ''', (username, password, password_hash, service, description))
    
    # Create some additional tables that might be interesting
    cursor.execute('''
        CREATE TABLE login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password TEXT,
            ip_address TEXT,
            success BOOLEAN,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            session_token TEXT,
            ip_address TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME
        )
    ''')
    

    
    conn.commit()
    conn.close()
    
    print(f"✅ Created SQLite database: {db_path}")
    print(f"📊 Total users: {len(users_data)}")
    print(f"👑 Admin users: {len(admin_data)}")
    print(f"🔧 System accounts: {len(system_data)}")


def create_credential_files():
    """Create additional credential files in various formats"""
    
    # Create a simple text file with credentials
    with open("passwords.txt", "w") as f:
        f.write("# Common passwords found on this system\n")
        f.write("# Use with Hydra or other brute force tools\n\n")
        f.write("admin:admin\n")
        f.write("root:root\n")
        f.write("user:user\n")
        f.write("test:test\n")
        f.write("guest:guest\n")
        f.write("demo:demo\n")
        f.write("temp:temp\n")
        f.write("admin:AdminPass2024!\n")
        f.write("root:RootPassword123!\n")
        f.write("john.doe:Password123!\n")
        f.write("jane.smith:Welcome2024\n")
        f.write("mike.wilson:SecurePass1\n")
        f.write("sarah.jones:MyPassword123\n")
        f.write("david.brown:Brown2024!\n")
        f.write("lisa.garcia:LisaPass123\n")
        f.write("robert.taylor:Robert123\n")
        f.write("amanda.white:Amanda2024\n")
        f.write("chris.lee:ChrisLee123\n")
        f.write("jennifer.martin:Jen2024!\n")
        f.write("ftp:ftp123\n")
        f.write("backup:backup2024\n")
        f.write("monitor:monitor123\n")
        f.write("mysql:MySQLPass123!\n")
        f.write("postgres:Postgres2024!\n")
        f.write("apache:Apache123!\n")
        f.write("nginx:Nginx2024!\n")
        f.write("redis:RedisPass123!\n")
        f.write("elasticsearch:Elastic2024!\n")
        f.write("jenkins:Jenkins123!\n")
        f.write("git:GitPass2024!\n")
    
    # Create a CSV file
    with open("user_credentials.csv", "w") as f:
        f.write("username,password,email,full_name,department,role\n")
        f.write("admin,admin,admin@company.com,Administrator,IT,admin\n")
        f.write("root,root,root@company.com,Root User,System,admin\n")
        f.write("john.doe,Password123!,john.doe@company.com,John Doe,IT,developer\n")
        f.write("jane.smith,Welcome2024,jane.smith@company.com,Jane Smith,Finance,analyst\n")
        f.write("mike.wilson,SecurePass1,mike.wilson@company.com,Mike Wilson,HR,manager\n")
        f.write("sarah.jones,MyPassword123,sarah.jones@company.com,Sarah Jones,Marketing,coordinator\n")
        f.write("david.brown,Brown2024!,david.brown@company.com,David Brown,IT,admin\n")
        f.write("lisa.garcia,LisaPass123,lisa.garcia@company.com,Lisa Garcia,Sales,representative\n")
        f.write("robert.taylor,Robert123,robert.taylor@company.com,Robert Taylor,Operations,supervisor\n")
        f.write("amanda.white,Amanda2024,amanda.white@company.com,Amanda White,Finance,accountant\n")
        f.write("chris.lee,ChrisLee123,chris.lee@company.com,Chris Lee,IT,developer\n")
        f.write("jennifer.martin,Jen2024!,jennifer.martin@company.com,Jennifer Martin,HR,specialist\n")
        f.write("ftp,ftp123,ftp@company.com,FTP Service,Services,service\n")
        f.write("backup,backup2024,backup@company.com,Backup Service,Services,service\n")
        f.write("monitor,monitor123,monitor@company.com,Monitoring Service,Services,service\n")
    
    
    print("✅ Created credential files:")
    print("   📄 passwords.txt - Simple username:password format")
    print("   📊 user_credentials.csv - CSV format with user details")
    print("   🔤 hydra_wordlist.txt - Hydra-compatible wordlist")

if __name__ == "__main__":
    print("🔐 Creating honeypot credential database and files...")
    print("=" * 60)
    
    create_credentials_database()
    print()
    create_credential_files()
    
    print("\n" + "=" * 60)
    print("🎯 Honeypot credentials created successfully!")
    print("\n📁 Files created:")
    print("   🗄️  user_credentials.db - SQLite database")
    print("   📄 passwords.txt - Username:password pairs")
    print("   📊 user_credentials.csv - CSV format")