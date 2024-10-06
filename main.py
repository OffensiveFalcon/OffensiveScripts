import requests
import urllib.parse
from bs4 import BeautifulSoup
import argparse
import sys
import time
from art import text2art
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# ASCII art for "OffensiveFalcon"
ascii_signature = text2art("""Offensive
Falcon""", font='Graffiti')
colored_signature = f"{Fore.CYAN}{ascii_signature}{Style.RESET_ALL}"
colored_signature += f"{Fore.GREEN}\n                                   Made by Mradul Umrao{Style.RESET_ALL}\n"
print(colored_signature)

# Load payloads from a file
def load_payloads_from_file(file_path):
    try:
        with open(file_path, 'r') as f:
            payloads = [line.strip() for line in f if line.strip()]
        if not payloads:
            raise ValueError("No payloads found in the file.")
        return payloads
    except FileNotFoundError:
        print(f"{Fore.RED}Error: File not found: {file_path}{Style.RESET_ALL}")
        sys.exit(1)
    except ValueError as ve:
        print(f"{Fore.RED}Error: {ve}{Style.RESET_ALL}")
        sys.exit(1)

# Get all forms on the page
def get_all_forms(url):
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an error for bad responses
    except requests.RequestException as e:
        print(f"{Fore.RED}Error while accessing {url}: {e}{Style.RESET_ALL}")
        sys.exit(1)

    soup = BeautifulSoup(response.text, 'html.parser')
    forms = soup.find_all('form')
    return forms

# Get form details (action, method, inputs)
def get_form_details(form):
    details = {}
    action = form.get('action')
    method = form.get('method', 'GET')  # Default to GET if not specified
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

    try:
        if method.lower() == 'post':
            response = requests.post(action, data=data)
        else:
            response = requests.get(action, params=data)
        response.raise_for_status()  # Raise an error for bad responses
    except requests.RequestException as e:
        print(f"{Fore.RED}Error while submitting form to {action}: {e}{Style.RESET_ALL}")
        return None

    return response

# Check for various vulnerabilities
def check_xss(url, payload):
    try:
        response = requests.get(url, params={'param': payload})
        response.raise_for_status()
    except requests.RequestException as e:
        print(f"{Fore.RED}Error while checking XSS: {e}{Style.RESET_ALL}")
        return False, None
    return payload in response.text, response.text

def check_sql_injection(url, payload):
    try:
        response = requests.get(url, params={'param': payload})
        response.raise_for_status()
    except requests.RequestException as e:
        print(f"{Fore.RED}Error while checking SQL Injection: {e}{Style.RESET_ALL}")
        return False, None
    return "syntax error" in response.text.lower() or "sql error" in response.text.lower(), response.text

def check_command_injection(url, payload):
    try:
        response = requests.get(url, params={'param': payload})
        response.raise_for_status()
    except requests.RequestException as e:
        print(f"{Fore.RED}Error while checking Command Injection: {e}{Style.RESET_ALL}")
        return False, None
    return "ls" in response.text, response.text

# Main function to test for vulnerabilities
def test_vulnerabilities(url, payloads, vuln_type, verbose=False, output_file=None, suppress_output=False, timing=1):
    result_log = []

    def log_result(message):
        if not suppress_output:
            print(message)
        if output_file:
            result_log.append(message)

    log_result(f"{Fore.YELLOW}Testing URL: {url}{Style.RESET_ALL}")

    # Test for vulnerabilities
    if vuln_type == 'XSS':
        log_result(f"{Fore.BLUE}--- Testing for XSS vulnerabilities ---{Style.RESET_ALL}")
        for payload in payloads:
            time.sleep(timing)
            found, response_text = check_xss(url, payload)
            if found:
                log_result(f"XSS vulnerability found with payload: {payload}")
                log_result(f"Response snippet: {response_text[:500]}")
    elif vuln_type == 'SQL':
        log_result(f"{Fore.BLUE}--- Testing for SQL Injection vulnerabilities ---{Style.RESET_ALL}")
        for payload in payloads:
            time.sleep(timing)
            found, response_text = check_sql_injection(url, payload)
            if found:
                log_result(f"SQL Injection vulnerability found with payload: {payload}")
                log_result(f"Response snippet: {response_text[:500]}")
    elif vuln_type == 'CMD':
        log_result(f"{Fore.BLUE}--- Testing for Command Injection vulnerabilities ---{Style.RESET_ALL}")
        for payload in payloads:
            time.sleep(timing)
            found, response_text = check_command_injection(url, payload)
            if found:
                log_result(f"Command Injection vulnerability found with payload: {payload}")
                log_result(f"Response snippet: {response_text[:500]}")

    # Testing forms
    log_result(f"{Fore.BLUE}--- Testing forms on the page ---{Style.RESET_ALL}")
    forms = get_all_forms(url)
    for i, form in enumerate(forms, 1):
        form_details = get_form_details(form)
        log_result(f"Testing form {i}: action={form_details['action']}, method={form_details['method']}")
        for payload in payloads:
            time.sleep(timing)
            response = submit_form(form_details, url, payload)
            if response and payload in response.text:
                log_result(f"{vuln_type} vulnerability found in form with payload: {payload}")
                log_result(f"Response snippet: {response.text[:500]}")

    # Write to output file
    if output_file:
        try:
            with open(output_file, 'w') as f:
                f.write("\n".join(result_log))
            log_result(f"{Fore.GREEN}Results written to {output_file}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Error writing to file: {e}{Style.RESET_ALL}")

# Function to handle subdomain or directory scanning
def handle_subdomain_or_directory(url, subdirectory=None, subdomain=None):
    # Automatically discover subdomains and directories (placeholder)
    discovered_urls = []
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
    parser.add_argument("--vuln-types", nargs='+', required=True, choices=["XSS", "SQL", "CMD"], help="Types of vulnerabilities to test for (XSS, SQL, CMD).")
    parser.add_argument("-o", "--output", help="File to store results.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode.")
    parser.add_argument("-t", "--timing", type=int, choices=[1, 2, 3, 4, 5], default=3, help="Set timing template like Nmap.")
    parser.add_argument("-k", "--subdirectory", help="Test a specific subdirectory.")
    parser.add_argument("-s", "--subdomain", help="Test a specific subdomain.")
    parser.add_argument("--payload-files", nargs='+', required=True, help="Payload files for each vulnerability type.")
    parser.add_argument("--suppress-output", action="store_true", help="Suppress terminal output, only save to file.")

    args = parser.parse_args()

    # Timing map
    timing_map = {
        1: 5,   # Paranoid
        2: 3,   # Sneaky
        3: 1,   # Normal
        4: 0.5, # Fast
        5: 0.1  # Aggressive
    }
    timing = timing_map.get(args.timing, 1)

    # Adjust URL for subdirectory or subdomain if specified
    url = handle_subdomain_or_directory(args.url, args.subdirectory, args.subdomain)

    # Loop through vulnerability types and payload files
    for vuln_type, payload_file in zip(args.vuln_types, args.payload_files):
        payloads = load_payloads_from_file(payload_file)
        test_vulnerabilities(url, payloads, vuln_type, args.verbose, args.output, args.suppress_output, timing)
