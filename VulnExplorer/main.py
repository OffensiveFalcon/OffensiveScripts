import os
import subprocess
import argparse
import json

class WebVulnerabilityScanner:
    def __init__(self, url, output_dir):
        self.url = url
        self.output_dir = output_dir
        self.vulnerabilities = []

    def clone_website(self):
        print("Cloning website using httrack...")
        command = f"httrack {self.url} -O {self.output_dir}"
        subprocess.run(command, shell=True)

    def scan_vulnerabilities(self):
        print("Scanning for vulnerabilities using nikto...")
        command = f"nikto -h {self.url} -output {self.output_dir}/nikto_output.txt"
        subprocess.run(command, shell=True)

        with open(f"{self.output_dir}/nikto_output.txt", "r") as file:
            lines = file.readlines()
            for line in lines:
                if "Vulnerability" in line:
                    self.vulnerabilities.append(line.strip())

    def exploit_vulnerabilities(self):
        print("Exploiting vulnerabilities using curl...")
        for vulnerability in self.vulnerabilities:
            # Assuming the vulnerability is in the format "Vulnerability: <vulnerability_name> (exploit: <exploit_command>)"
            parts = vulnerability.split(": ")
            vulnerability_name = parts[1].split(" (")[0]
            exploit_command = parts[1].split(" (")[1].replace(")", "")

            command = f"curl -X POST -d '{exploit_command}' {self.url}"
            subprocess.run(command, shell=True)

    def write_results_to_file(self):
        print("Writing results to file...")
        with open(f"{self.output_dir}/results.txt", "w") as file:
            file.write("Vulnerabilities:\n")
            for vulnerability in self.vulnerabilities:
                file.write(vulnerability + "\n")

def main():
    parser = argparse.ArgumentParser(description="Web Vulnerability Scanner")
    parser.add_argument("-u", "--url", help="URL of the website to scan", required=True)
    parser.add_argument("-o", "--output-dir", help="Directory to store the output", required=True)
    args = parser.parse_args()

    scanner = WebVulnerabilityScanner(args.url, args.output_dir)

    while True:
        print("\nMenu:")
        print("1. Clone website")
        print("2. Scan for vulnerabilities")
        print("3. Exploit vulnerabilities")
        print("4. Write results to file")
        print("5. Exit")

        choice = input("Enter your choice: ")

        if choice == "1":
            scanner.clone_website()
        elif choice == "2":
            scanner.scan_vulnerabilities()
        elif choice == "3":
            scanner.exploit_vulnerabilities()
        elif choice == "4":
            scanner.write_results_to_file()
        elif choice == "5":
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
