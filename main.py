import requests
import re
import urllib.parse
from bs4 import BeautifulSoup
import argparse
import sys
import time
import os
from art import text2art
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Generate ASCII art for "OffensiveFalcon"
ascii_signature = text2art("Offensive\nFalcon", font='Graffiti')
colored_signature = f"{Fore.CYAN}{ascii_signature}{Style.RESET_ALL}"
colored_signature += f"{Fore.GREEN}\n                                   Made by Mradul Umrao{Style.RESET_ALL}\n"
print(colored_signature)

# Function to load payloads from external file
def load_payloads_from_file(file_path):
    try:
        with open(file_path, 'r') as f:
            payloads = [line.strip() for line in f if line.strip()]
        return payloads
    except FileNotFoundError:
        print(f"Error: File not found: {file_path}")
        sys.exit(1)

# Get all forms on the page
def get_all_forms(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    forms = soup.find_all('form')
    return forms

# Get form details (action, method, inputs)
def get_form_details(form):
    details = {}
    action = form.get('action')
    method = form.get('method')
    inputs = form.find_all('input')
    details['action'] = action
    details['method'] = method
    details['inputs'] = inputs
    return details

# Submit the form with a payload
def submit_form(form_details, base_url, payload):
    action = form_details['action']
    if action.startswith('/'):
        action = urllib.parse.urljoin(base_url, action)
    elif not action.startswith('http'):
        action = base_url + action

    method = form_details['method']
    inputs = form_details['inputs']
    data = {}
    for input in inputs:
        name = input.get('name')
        value = input.get('value')
        if name:
            data[name] = value
    data['param'] = payload
    if method.lower() == 'post':
        response = requests.post(action, data=data)
    else:
        response = requests.get(action, params=data)
    return response

# Function to check for XSS vulnerabilities
def check_xss(url, payload):
    response = requests.get(url, params={'param': payload})
    if payload in response.text:
        return True, response.text
    return False, None

# Function to check for SQL Injection vulnerabilities
def check_sql_injection(url, payload):
    response = requests.get(url, params={'param': payload})
    if "syntax error" in response.text.lower() or "sql error" in response.text.lower():
        return True, response.text
    return False, None

# Function to check for Command Injection vulnerabilities
def check_command_injection(url, payload):
    response = requests.get(url, params={'param': payload})
    if "ls" in response.text:
        return True, response.text
    return False, None

# Main function to test for vulnerabilities
def test_vulnerabilities(url, payloads, vuln_type, verbose=False, output_file=None, timing=1):
    result_log = []

    def log_result(message):
        if output_file:
            result_log.append(message)
        if verbose:
            print(message)

    log_result(f"Testing URL: {url}")

    # Test specified vulnerabilities
    if vuln_type == 'XSS':
        log_result("Testing for XSS vulnerabilities:")
        for payload in payloads:
            time.sleep(timing)
            found, response_text = check_xss(url, payload)
            if found:
                log_result(f"XSS vulnerability found with payload: {payload}")
                log_result(f"Exploited XSS result: {response_text[:500]}")

    elif vuln_type == 'SQL':
        log_result("Testing for SQL Injection vulnerabilities:")
        for payload in payloads:
            time.sleep(timing)
            found, response_text = check_sql_injection(url, payload)
            if found:
                log_result(f"SQL Injection vulnerability found with payload: {payload}")
                log_result(f"Exploited SQL Injection result: {response_text[:500]}")

    elif vuln_type == 'CMD':
        log_result("Testing for Command Injection vulnerabilities:")
        for payload in payloads:
            time.sleep(timing)
            found, response_text = check_command_injection(url, payload)
            if found:
                log_result(f"Command Injection vulnerability found with payload: {payload}")
                log_result(f"Exploited Command Injection result: {response_text[:500]}")

    # Testing forms
    log_result("Testing forms:")
    forms = get_all_forms(url)
    for i, form in enumerate(forms, 1):
        form_details = get_form_details(form)
        log_result(f"Testing form {i}: action={form_details['action']}, method={form_details['method']}")
        for payload in payloads:
            time.sleep(timing)
            response = submit_form(form_details, url, payload)
            if payload in response.text:
                log_result(f"{vuln_type} vulnerability found in form with payload: {payload}")
                log_result(f"Exploited {vuln_type} form result: {response.text[:500]}")

    # Write to output file
    if output_file:
        with open(output_file, 'w') as f:
            f.write("\n".join(result_log))
        log_result(f"Results written to {output_file}")

# Main entry point
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Vulnerability scanner with external payloads.")
    parser.add_argument("url", help="The target URL to test.")
    parser.add_argument("--vuln-type", required=True, choices=["XSS", "SQL", "CMD"], help="Type of vulnerability to test for (XSS, SQL, CMD).")
    parser.add_argument("-o", "--output", help="File to store results.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode.")
    parser.add_argument("-t", "--timing", type=int, choices=[1, 2, 3, 4, 5], default=3, help="Set timing template like Nmap (1: Paranoid, 5: Aggressive).")
    parser.add_argument("-k", "--subdirectory", help="Test a specific subdirectory.")
    parser.add_argument("-s", "--subdomain", help="Test a specific subdomain.")
    parser.add_argument("--payload-file", help="External payload file to use.", required=True)
    parser.add_argument("--target", help="Specify the target IP address or URL.")
    parser.add_argument("--log-file", help="File to save the output log.")

    args = parser.parse_args()

    # Load payloads from the specified file
    payloads = load_payloads_from_file(args.payload_file)
    if not payloads:
        sys.exit("No payloads found. Please provide a valid payload file.")

    # Use the target argument if provided; otherwise, use the URL
    target_url = args.target if args.target else args.url

    # Test vulnerabilities
    test_vulnerabilities(target_url, payloads, args.vuln_type, args.verbose, args.output, args.timing)
