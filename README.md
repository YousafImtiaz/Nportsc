# Nportsc (N-port-sc) (Nmap Port Scan)

## Overview
Nportsc is an Nmap port scanning script written in Python with ChatGPT that automates the process of running quick and detailed Nmap scans for TCP and UDP ports. The scan is displayed in the terminal and also outputs to a file as well for later. After the scan is fully complete the open ports found will be grepped out into a highlighted list at the bottom of the terminal.

## Features
- Scanning of both TCP and UDP ports using Nmap.
- Can add extra flags in the terminal as needed such as -Pn 
- Scan speed can be adjusted based on your environment
- After scan is complete, will grep out open ports automatically with services
- Detailed scan outputs to a txt file 

## Requirements
- Python 3.x
- Nmap
- Sudo privileges: The script requires `sudo` to run because it allows Nmap to perform scans faster and more efficiently

## Usage
To use the script, run the following command in your terminal:

sudo python3 nportsc.py $target-ip --tcp (T1,T2,T3,T4,T5) $extra flags # For TCP scan

sudo python3 nportsc.py $target-ip --udp (T1,T2,T3,T4,T5) $extra flags # For UDP scan

## Output

The results of the detailed scan will be saved to a text file: 
(target_ip)_(scan type)_nmap.txt 
Each port that is scanned will also be seperated in the output, making it easier to look through.
