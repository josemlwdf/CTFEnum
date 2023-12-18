# CTFEnum - Network Penetration Test Tool

## Overview
CTFEnum is a Python-based tool designed to assist in network penetration tests, particularly for Capture The Flag (CTF) challenges. It performs reconnaissance by scanning and analyzing open ports on a provided IP address. The tool uses various modules to probe different services associated with these open ports. Employing multiprocessing, it concurrently executes different modules to identify potential vulnerabilities across multiple ports.

## Features
Scans open TCP and UDP ports using Nmap.
Utilizes modular design with specific handlers for different services (e.g., FTP, Telnet, SMTP, HTTP, DNS, Kerberos, etc.).
Provides recommendations and potential actions for specific ports (e.g., brute force attempts, service-specific commands).

## Requirements
``Python 3.x
Nmap
Gobuster
Dig
Crackmapexec
Metasploit
Required Python libraries: subprocess, multiprocessing, sys, re, etc...``

## Installation
    curl https://raw.githubusercontent.com/josemlwdf/CTFEnum/main/install.sh|bash

## Usage

Run the tool by providing the IP address as an argument:

    python CTFEnum.py <IP_ADDRESS>

Replace <IP_ADDRESS> with the target IP address you intend to scan.

The program will perform a comprehensive port scan using Nmap to identify open TCP and UDP ports on the specified IP address.

CTFEnum will then initiate module-specific handlers based on identified open ports to analyze and potentially exploit services running on these ports.

## Notes

``The tool suggests actions for certain ports, such as potential brute force attempts or specific commands to execute.
For optimal usage, ensure proper permissions and avoid using this tool on networks you don't have authorization to test.``

## Disclaimer

This tool is intended for educational and ethical penetration testing purposes only. Ensure that you have proper authorization before using it on any network or system you do not own or have explicit permission to test.
