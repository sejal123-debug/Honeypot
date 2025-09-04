import argparse
from ssh_honeypot import start_ssh_honeypot
from web_honeypot import start_web_honeypot
from ftp_honeypot import start_ftp_honeypot

def main():
    # 1. Create the top-level parser
    parser = argparse.ArgumentParser(
        description="Honeypie: A simple Python-based honeypot to capture attacker data."
    )
    
    # 2. Add common arguments that any honeypot might need
    parser.add_argument(
        '-a', '--address',
        default='0.0.0.0',  # Listen on all network interfaces
        help='The IP address to bind to (default: 0.0.0.0)'
    )
    
    # 3. Create subparsers for the different honeypot types (SSH, HTTP)
    subparsers = parser.add_subparsers(
        dest='service',  # This will store the chosen service ('ssh' or 'http')
        required=True,   # Force the user to choose one
        help='Type of honeypot service to run'
    )

    # 4. Create the parser for the SSH service
    parser_ssh = subparsers.add_parser(
        'ssh',
        help='Run the SSH honeypot service'
    )
    # SSH-specific arguments
    parser_ssh.add_argument(
        '-p', '--port',
        type=int,
        default=2222,  # Default port for our SSH honeypot
        help='Port to listen on (default: 2222)'
    )
    parser_ssh.add_argument(
        '-u', '--username',
        help='A specific username to accept (accepts any if not set)'
    )
    parser_ssh.add_argument(
        '-pw', '--password',
        help='A specific password to accept (accepts any if not set)'
    )

    # 5. Create the parser for the HTTP service
    parser_http = subparsers.add_parser(
        'http',
        help='Run the HTTP (Web) honeypot service'
    )
    # HTTP-specific arguments
    parser_http.add_argument(
        '-p', '--port',
        type=int,
        default=8080,  # Default port for our web honeypot
        help='Port to listen on (default: 8080)'
    )
    parser_http.add_argument(
        '-u', '--username',
        default='admin',  # Common default for web logins
        help='Username to present on the login page (default: admin)'
    )
    parser_http.add_argument(
        '-pw', '--password',
        default='password', # Common default for web logins
        help='Password to present on the login page (default: password)'
    )

    # 6. Create the parser for the FTP service
    parser_ftp = subparsers.add_parser(
        'ftp',
        help='Run the FTP honeypot service'
    )
    # FTP-specific arguments
    parser_ftp.add_argument(
        '-p', '--port',
        type=int,
        default=2121,  # Default port for our FTP honeypot
        help='Port to listen on (default: 2121)'
    )
    parser_ftp.add_argument(
        '-u', '--username',
        help='A specific username to accept (accepts any if not set)'
    )
    parser_ftp.add_argument(
        '-pw', '--password',
        help='A specific password to accept (accepts any if not set)'
    )
    # 7. Parse the command-line arguments
    args = parser.parse_args()

    # 8. Based on the chosen service, call the appropriate function with the arguments
    if args.service == 'ssh':
        print(f"[+] Starting SSH Honeypot on {args.address}:{args.port}")
        # Call the function from ssh_honeypot.py, passing the arguments
        start_ssh_honeypot(args.address, args.port, args.username, args.password)
    elif args.service == 'http':
        print(f"[+] Starting HTTP Honeypot on {args.address}:{args.port}")
        # Call the function from web_honeypot.py, passing the arguments
        start_web_honeypot(args.address, args.port, args.username, args.password)
    elif args.service == 'ftp':
        print(f"[+] Starting FTP Honeypot on {args.address}:{args.port}")
        # Call the function from ftp_honeypot.py, passing the arguments
        start_ftp_honeypot(args.address, args.port, args.username, args.password)

# This standard line ensures the code runs only when executed directly (not imported)
if __name__ == '__main__':
    main()