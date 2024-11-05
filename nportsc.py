#!/usr/bin/python3

import subprocess
import sys
import re
import argparse
import os

# ANSI escape code for orange
ORANGE = "\033[38;5;214m"  # Using a specific 256-color orange
RESET = "\033[0m"  # Reset to default color

def check_sudo():
    """Check if the script is running with sudo (root privileges)."""
    if os.geteuid() != 0:
        print("This script must be run with sudo privileges. Please run again with 'sudo'.")
        sys.exit(1)

def print_banner():
    """Print the banner for Nportsc."""
    banner_text = "Nportsc"
    print(f"{ORANGE}{banner_text}{RESET}")  # Print in orange

def format_output_for_readability(scan_output):
    """Format the Nmap output by adding a blank line between each port entry."""
    formatted_output = []
    lines = scan_output.splitlines()
    
    for i, line in enumerate(lines):
        formatted_output.append(line)
        # Add a blank line after each line that contains a port entry, 
        # but avoid adding one after the last port entry.
        if re.match(r'^\d+/(tcp|udp)', line) and i < len(lines) - 1:
            formatted_output.append('')  # Add a blank line

    return "\n".join(formatted_output)

def run_nmap_quick_scan(target_ip, scan_type, timing_template):
    """Run the quick Nmap scan on the target IP for either TCP or UDP."""
    if scan_type == 'tcp':
        print(f"Running quick TCP scan on {target_ip} with timing template {timing_template}...")
        command = ["sudo", "nmap", "-p-", f"-{timing_template}", "--open", target_ip]
    elif scan_type == 'udp':
        print(f"Running quick UDP scan on {target_ip} with timing template {timing_template}...")
        command = ["sudo", "nmap", "-sU", "--top-ports=100", "--open", f"-{timing_template}", target_ip]  # -sU flag for UDP scanning

    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode != 0:
            print("Error running nmap:", result.stderr)
            sys.exit(1)

        print(result.stdout)
        return result.stdout
    except Exception as e:
        print("An error occurred:", str(e))
        sys.exit(1)

def extract_open_ports(scan_output):
    """Extract open ports from the scan output."""
    open_ports = []
    for line in scan_output.splitlines():
        match = re.match(r'^\s*(\d+)/tcp\s+open', line)  # Extract TCP ports
        if match:
            open_ports.append(match.group(1))
        
        match_udp = re.match(r'^\s*(\d+)/udp\s+open', line)  # Extract UDP ports
        if match_udp:
            open_ports.append(match_udp.group(1))
            
    return open_ports

def run_nmap_detail_scan(target_ip, open_ports, scan_type):
    """Run a detailed Nmap scan on the open ports for either TCP or UDP."""
    if not open_ports:
        print("No open ports found. Exiting.")
        return
    
    ports = ','.join(open_ports)
    if scan_type == 'tcp':
        print(f"Running detailed TCP scan on open ports: {ports}...")
        command = ["sudo", "nmap", "-p", ports, target_ip, "-A"]
        output_file = "nmaptcp.txt"  # Save TCP scan to nmaptcp.txt
    elif scan_type == 'udp':
        print(f"Running detailed UDP scan on open ports: {ports}...")
        command = ["sudo", "nmap", "-sU", "-p", ports, "-sV", target_ip]
        output_file = "nmapudp.txt"  # Save UDP scan to nmapudp.txt

    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode != 0:
            print("Error running nmap:", result.stderr)
            sys.exit(1)

        # Format the output for readability
        formatted_output = format_output_for_readability(result.stdout)

        with open(output_file, "w") as outfile:
            outfile.write(formatted_output)

        print(f"Detailed scan results saved to {output_file}.")
        
        # Open the output file automatically as a normal user and exit the script
        print(f"Opening {output_file}...")
        subprocess.Popen(["sudo", "-u", os.getlogin(), "mousepad", output_file])
    except Exception as e:
        print("An error occurred:", str(e))
        sys.exit(1)

def main():
    # Ensure the script is running with sudo privileges
    check_sudo()

    print_banner()

    # Argument parsing
    parser = argparse.ArgumentParser(description='Nmap TCP/UDP Scanner')
    parser.add_argument('target_ip', help='Target IP address to scan')
    parser.add_argument('--tcp', action='store_true', help='Run TCP scan')
    parser.add_argument('--udp', action='store_true', help='Run UDP scan')
    parser.add_argument('timing_template', choices=['T1', 'T2', 'T3', 'T4', 'T5'], help='Specify Nmap timing template (T1 to T5)')

    args = parser.parse_args()

    if not args.tcp and not args.udp:
        print("Please specify --tcp or --udp to select the scan type.")
        sys.exit(1)

    scan_type = 'tcp' if args.tcp else 'udp'
    target_ip = args.target_ip
    timing_template = args.timing_template

    try:
        scan_output = run_nmap_quick_scan(target_ip, scan_type, timing_template)
        open_ports = extract_open_ports(scan_output)
        run_nmap_detail_scan(target_ip, open_ports, scan_type)
    except KeyboardInterrupt:
        print("\nScan cancelled by the user.")
        sys.exit(0)  # Exit gracefully

if __name__ == "__main__":
    main()
