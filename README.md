# CTFEnum - Network Penetration Test Tool

## Overview
CTFEnum is a Python-based tool designed to assist in network penetration tests, particularly for Capture The Flag (CTF) challenges. It performs reconnaissance by scanning and analyzing open ports on a provided IP address. The tool uses various modules to probe different services associated with these open ports. Employing multiprocessing, it concurrently executes different modules to identify potential vulnerabilities across multiple ports.

## Features
Scans open TCP and UDP ports using Nmap.
Utilizes modular design with specific handlers for different services (e.g., FTP, Telnet, SMTP, HTTP, DNS, Kerberos, etc.).
Provides recommendations and potential actions for specific ports (e.g., brute force attempts, service-specific commands).

## Requirements
    Python 3.x
    Nmap
    Gobuster
    Dig
    Crackmapexec
    Metasploit
    etc...
    Required Python libraries: subprocess, multiprocessing, sys, re, etc...

## Installation
    curl https://raw.githubusercontent.com/josemlwdf/CTFEnum/main/install.sh|bash

## Usage

Run the tool by providing the IP address as an argument:

    python3 /application/path/CTFEnum.py <IP_ADDRESS>
    
If installed with install.sh:

    ctfenum <IP_ADDRESS>

Replace <IP_ADDRESS> with the target IP address you intend to scan.

The program will perform a comprehensive port scan using Nmap to identify open TCP and UDP ports on the specified IP address.

CTFEnum will then initiate module-specific handlers based on identified open ports to analyze and potentially exploit services running on these ports.

## Detailed Features (Modules)

#### NMAP Scan
- Automatic nmap ports detection + Nmap port details Scan.

![image](https://github.com/user-attachments/assets/da03d1b5-7a5e-455a-8219-c279a43b6674)
  
- Scraps for DNS from Nmpa Scan.

#### FTP 
- Check for anonymous login.
- Bruteforce using common users and passwords.
- List directories.

#### SSH
- Suggests SSH credentials bruteforce.

![image](https://github.com/user-attachments/assets/e41add59-55f3-4489-9008-7875981f3d50)

#### TELNET
- Retrieve Nmap information using this service specific scripts.

#### SMTP
- Retrieve Nmap information using this service specific scripts.

#### FINGER
- Enumerate users using this service.

#### HTTP
- Identify server and possible common technologies.
- Crawl and bruteforce locations using feroxbuster.

![image](https://github.com/user-attachments/assets/19d75ed8-6292-4385-8a7f-46f435c3d75e)
  
- Detects VHOSTS and add them automatically to /etc/hosts file.
- Extract comments from the founded URLs.

![image](https://github.com/user-attachments/assets/7595168c-5909-4d9d-b411-8aef7e1d7b78)
  
- Test automatically for Apache Server CVEs if the version matches.

#### KERBEROS
- Kerberos usenames enumeration.
- Kerberoast Automatic ticket Extraction.
- Kerberos Atuomatic Synchronization with DC.
- Automatic Ticket Cracking (Optional).

#### POP
- Suggests POP credentials bruteforce.

#### RPC BIND
- Suggest Hacktrics page as reference.

#### IMAP
- Enumerates IMAP version.
- Suggests Hacktrics page as reference.

#### SMB
- RID Cycling usernames enumeration Attack as Guest.
- RID Cycling usernames enumeration Attack with founded credentials.
- Bruteforce using common users and passwords.
- Bruteforce using founded users.
- Bruteforce using options NULL pass, User as Pass and common passwords.
- Shares enumeration using NULL creds, Guest and founded credentials.

#### TFTP
- Check if TFTP server allow PUT files.

#### SNMP
- Automatic Nmap SNMP targeted scan.
- Community password bruteforce.
- Automatic strings extraction.

#### DNS
- Perform dig scan on DNS.
- Automatic DNS registration on /etc/hosts file.

## Notes

``The tool suggests actions for certain ports, such as potential brute force attempts or specific commands to execute.
For optimal usage, ensure proper permissions and avoid using this tool on networks you don't have authorization to test.``

## Disclaimer

This tool is intended for educational and ethical penetration testing purposes only. Ensure that you have proper authorization before using it on any network or system you do not own or have explicit permission to test.
