# Nportsc N-port-sc (Nmap Port Scan)

## Overview
Nportsc is an Nmap port scanning script written in Python using ChatGPT that automates the process of running quick and detailed Nmap scans for TCP and UDP ports. The quick scan is displayed in the terminal so you can start enumerating ports such as port 80, while the detailed scan runs and outputs to a file, allowing for efficient multitasking when doing CTF machines or exams such as the OSCP.

## Features
- Quick scanning of TCP and UDP ports using Nmap.
- Detailed scanning of open ports to retrieve service and version information.
- Output formatting for better readability.
- Automatically opens scan results in a text editor.
- Scan speed can be adjusted based on your environment

## Requirements
- Python 3.x
- Nmap
- Mousepad
- Sudo privileges: The script requires `sudo` to run because it allows Nmap to perform scans faster and more efficiently

## Usage
To use the script, run the following command in your terminal:

sudo python3 nportsc.py <target-ip> --tcp (T1,T2,T3,T4,T5)  # For TCP scan

sudo python3 nportsc.py <target-ip> --udp (T1,T2,T3,T4,T5)  # For UDP scan

## Output

The results of the detailed scan will be saved to a text file (nmaptcp.txt for TCP scans and nmapudp.txt for UDP scans) and automatically opened in a text editor. Each port that is scanned will also be seperated, making it easier to read.
