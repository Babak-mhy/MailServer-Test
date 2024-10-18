import socket
import dns.resolver
import smtplib
from datetime import datetime

# Ports used by mail servers
MAIL_PORTS = [25, 587, 465, 110, 995, 143, 993]

# Report storage dictionary
report = {
    'domain': '',
    'mx_records': [],
    'open_ports': {},
    'banners': {},
    'smtp_tests': {},
    'timestamp': '',
    'vulnerable': False
}

# Function to perform a simple port scan
def scan_ports(mail_server):
    open_ports = []
    for port in MAIL_PORTS:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((mail_server, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports

# Function to grab the banner from an open port
def banner_grab(mail_server, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    try:
        sock.connect((mail_server, port))
        banner = sock.recv(1024).decode().strip()
        return banner
    except Exception:
        return None
    finally:
        sock.close()

# Function to check the MX records for a domain
def check_mx_records(domain):
    try:
        result = dns.resolver.resolve(domain, 'MX')
        mx_records = [str(record.exchange)[:-1] for record in result]  # Clean up the dot at the end
        return mx_records
    except Exception:
        return []

# Function to test SMTP commands
def test_smtp_commands(mail_server):
    smtp_tests = {}
    try:
        server = smtplib.SMTP(mail_server, 25, timeout=10)
        server.ehlo_or_helo_if_needed()
        
        # Test VRFY command
        code, response = server.vrfy('root')
        smtp_tests['VRFY'] = 'Enabled' if code == 250 else 'Disabled'

        # Test EXPN command
        code, response = server.docmd('EXPN', 'root')
        smtp_tests['EXPN'] = 'Enabled' if code == 250 else 'Disabled'

        server.quit()
    except Exception:
        smtp_tests['VRFY'] = 'Failed'
        smtp_tests['EXPN'] = 'Failed'
    return smtp_tests

# Function to determine if the mail server is vulnerable
def is_vulnerable(report):
    # Check if VRFY or EXPN commands are enabled
    for server, smtp_test in report['smtp_tests'].items():
        if smtp_test.get('VRFY') == 'Enabled' or smtp_test.get('EXPN') == 'Enabled':
            return True
    
    # Check if the banner contains detailed software version information
    for (server, port), banner in report['banners'].items():
        if banner and ("Postfix" in banner or "Exim" in banner or "Sendmail" in banner):
            return True
    
    return False

# Function to save the report to a file
def save_report(report):
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_filename = f"mail_server_report_{report['domain']}_{timestamp}.txt"
    
    with open(report_filename, 'w') as f:
        f.write(f"Mail Server Penetration Test Report for {report['domain']}\n")
        f.write(f"Timestamp: {report['timestamp']}\n")
        f.write("="*50 + "\n")
        
        # MX Records
        f.write("MX Records:\n")
        for mx in report['mx_records']:
            f.write(f" - {mx}\n")
        
        f.write("="*50 + "\n")
        
        # Open Ports and Banners
        f.write("Open Ports and Banners:\n")
        for server, ports in report['open_ports'].items():
            f.write(f"\nMail Server: {server}\n")
            for port in ports:
                f.write(f" - Port {port} is open.\n")
                banner = report['banners'].get((server, port), "No banner")
                f.write(f"   Banner: {banner}\n")
        
        f.write("="*50 + "\n")
        
        # SMTP Commands
        f.write("SMTP Command Tests:\n")
        for server, smtp_test in report['smtp_tests'].items():
            f.write(f"\nMail Server: {server}\n")
            for cmd, status in smtp_test.items():
                f.write(f" - {cmd}: {status}\n")
        
        f.write("="*50 + "\n")
        
        # Vulnerability Status
        if report['vulnerable']:
            f.write("Potential Vulnerability: YES\n")
            f.write("Reason: Server allows VRFY/EXPN or discloses software version.\n")
        else:
            f.write("Potential Vulnerability: NO\n")
        
    print(f"Report saved to {report_filename}")

# Main function to run the penetration test
def mail_server_penetration_test(domain):
    # Set report details
    report['domain'] = domain
    report['timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    mx_records = check_mx_records(domain)
    if not mx_records:
        print("No MX records found. Exiting...")
        return
    report['mx_records'] = mx_records
    
    for mx in mx_records:
        open_ports = scan_ports(mx)
        report['open_ports'][mx] = open_ports
        
        for port in open_ports:
            banner = banner_grab(mx, port)
            report['banners'][(mx, port)] = banner
        
        if 25 in open_ports:
            smtp_tests = test_smtp_commands(mx)
            report['smtp_tests'][mx] = smtp_tests
    
    # Check if the server is vulnerable based on the tests
    report['vulnerable'] = is_vulnerable(report)
    
    # Save the report
    save_report(report)

# Example Usage
if __name__ == "__main__":
    domain = input("Enter the domain to test: ")
    mail_server_penetration_test(domain)
