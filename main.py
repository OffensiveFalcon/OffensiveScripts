import requests
import re
import urllib.parse
from bs4 import BeautifulSoup
import argparse
import sys
import time
import os
from art import text2art  # Importing the art library for ASCII art
from colorama import Fore, Style, init  # Importing colorama

# Initialize colorama
init(autoreset=True)

# Generate ASCII art for "OffensiveFalcon" using a smaller font
ascii_signature = text2art("""Offensive
Falcon""", font='Graffiti')  # Set the font to small

# Change color (you can use Fore.RED, Fore.GREEN, etc.)
colored_signature = f"{Fore.CYAN}{ascii_signature}{Style.RESET_ALL}"

# Add made by message
colored_signature += f"{Fore.GREEN}\n                                   Made by Mradul Umrao{Style.RESET_ALL}\n"

print(colored_signature)


# Function to load payloads from external file
def load_payloads_from_file(file_path):
    try:
        with open(file_path, 'r') as f:
            payloads = [line.strip() for line in f if line.strip()]
        return payloads
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return []

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

# Function to test XSS vulnerabilities
def check_xss(url, payload):
    response = requests.get(url, params={'param': payload})
    if payload in response.text:
        return True, response.text
    return False, None

# Function to test SQL Injection vulnerabilities
def check_sql_injection(url, payload):
    response = requests.get(url, params={'param': payload})
    if "syntax error" in response.text.lower() or "sql error" in response.text.lower():
        return True, response.text
    return False, None

# Function to test Command Injection vulnerabilities
def check_command_injection(url, payload):
    response = requests.get(url, params={'param': payload})
    if "ls" in response.text:
        return True, response.text
    return False, None

# Main function to test for vulnerabilities
def test_vulnerabilities(url, payloads, vuln_type, verbose=False, output_file=None, timing=1):
    result_log = []

    def log_result(message):
        print(message)
        if output_file:
            result_log.append(message)

    log_result(f"Testing URL: {url}")

    # Test XSS vulnerabilities
    if vuln_type == 'XSS':
        log_result("Testing for XSS vulnerabilities:")
        xss_found = False
        for payload in payloads:
            time.sleep(timing)
            found, response_text = check_xss(url, payload)
            if found:
                log_result(f"XSS vulnerability found with payload: {payload}")
                log_result(f"Exploited XSS result: {response_text[:500]}")
                xss_found = True
        if not xss_found:
            log_result("No XSS vulnerabilities found.")

    # Test SQL Injection vulnerabilities
    elif vuln_type == 'SQL':
        log_result("Testing for SQL Injection vulnerabilities:")
        sql_found = False
        for payload in payloads:
            time.sleep(timing)
            found, response_text = check_sql_injection(url, payload)
            if found:
                log_result(f"SQL Injection vulnerability found with payload: {payload}")
                log_result(f"Exploited SQL Injection result: {response_text[:500]}")
                sql_found = True
        if not sql_found:
            log_result("No SQL Injection vulnerabilities found.")

    # Test Command Injection vulnerabilities
    elif vuln_type == 'CMD':
        log_result("Testing for Command Injection vulnerabilities:")
        cmd_found = False
        for payload in payloads:
            time.sleep(timing)
            found, response_text = check_command_injection(url, payload)
            if found:
                log_result(f"Command Injection vulnerability found with payload: {payload}")
                log_result(f"Exploited Command Injection result: {response_text[:500]}")
                cmd_found = True
        if not cmd_found:
            log_result("No Command Injection vulnerabilities found.")

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

# Function to handle subdomain or specific path scanning
def handle_subdomain_or_directory(url, subdirectory=None, subdomain=None):
    if subdirectory:
        return urllib.parse.urljoin(url, subdirectory)
    elif subdomain:
        parsed_url = urllib.parse.urlparse(url)
        return f"{parsed_url.scheme}://{subdomain}.{parsed_url.netloc}{parsed_url.path}"
    return url

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

    # Display help message
    args = parser.parse_args()

    # Timing map (similar to Nmap timing)
    timing_map = {
        1: 5,   # Paranoid, 5 seconds between requests
        2: 3,   # Sneaky
        3: 1,   # Normal
        4: 0.5, # Fast
        5: 0.1  # Aggressive
    }
    timing = timing_map.get(args.timing, 1)

    # Adjust URL for subdirectory or subdomain if specified
    url = handle_subdomain_or_directory(args.url, args.subdirectory, args.subdomain)

    # Load payloads from the specified file
    payloads = load_payloads_from_file(args.payload_file)
    if not payloads:
        sys.exit("No payloads found. Please provide a valid payload file.")

    # Test vulnerabilities
    test_vulnerabilities(url, payloads, args.vuln_type, args.verbose, args.output, timing)
