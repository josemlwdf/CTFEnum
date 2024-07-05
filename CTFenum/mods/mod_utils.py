from colorama import init, Fore, Back, Style
import re
import requests
import subprocess
import sys

# Initialize colorama
init()

YELLOW = 'YELLOW'
BLACK = 'BLACK'
RED = 'RED'
GREEN = 'GREEN'
BLUE = 'BLUE'
MAGENTA = 'MAGENTA'
CYAN = 'CYAN'
WHITE = 'WHITE'

max_subprocess = 200


def printc(text, color=None, back_color=None):
    if color is not None:
        colored_text = getattr(Fore, color.upper(), Fore.RESET) + Style.BRIGHT + text
    else:
        colored_text = Style.RESET_ALL + text

    if back_color is not None:
        colored_text = getattr(Back, back_color.upper(), Back.RESET) + colored_text

    print(colored_text + Style.RESET_ALL)


# Prints a command output separator
def print_separator():
    printc('=' * 70, YELLOW)


def print_banner(port):
    print_separator()
    printc(f'[!] Attacking port {port}', YELLOW)  


def scan_for_dns(nmap_detail):
    detail = nmap_detail.splitlines()

    for line in detail:
        if 'Domain:' in line:
            results = re.findall('Domain: (.+)0\.', line)
            if results:
                parts = results[0].split('.')
                if len(parts) > 1:
                    dns = f'{parts[-2]}.{parts[-1]}'.strip()
                    return dns
        elif 'DNS:' in line:
            results = re.findall('DNS:.+\.(.+\..+)', line)
            if results:
                dns = results[0].strip()
                return dns
        elif 'DNS_Domain_Name' in line:
            results = re.findall('DNS_Domain_Name: (.*)\n', line)
            if results:
                dns = results[0].strip()
                return dns
        elif 'DNS_Tree_Name' in line:
            results = re.findall('DNS_Tree_Name: (.*)\n', line)
            if results:
                dns = results[0].strip()
                return dns
        elif ('ssl-cert' in line) and ('commonName' in line):
            results = re.findall('commonName=(.*)\n', line)
            if results:
                parts = results[0].split('.')
                if len(parts) > 1:
                    dns = f'{parts[-2]}.{parts[-1]}'.strip()
                    return dns
    return ''


def clean_hosts(ip, subdomain=None):
    with open('/etc/hosts', 'r') as file:
        data = file.readlines()

    line_to_delete = []

    for line in data:
        if len(line) < 5:
            line_to_delete.append(line)
            continue
        elif ip in line:
            line_to_delete.append(line)
            continue
        if subdomain:
            if subdomain in line:
                line_to_delete.append(line)

    for line in line_to_delete:
        try:
            data.remove(line)
        except:
            continue

    with open('/etc/hosts', 'w') as file:
        new_data = ''.join(data)
        file.write(new_data)


# Starts a list of subprocesses and then wait for them to finish
def launch_procs(procs):
    while procs:
        try:
            running_procs = []

            # Launch subprocesses up to the maximum limit or until the end of the list
        
            for proc in procs[:max_subprocess]:
                proc.start()
                running_procs.append(proc)
        
            # Wait for the running subprocesses to finish
            for proc in running_procs:
                proc.join()

            # Remove finished subprocesses from the list
            procs = procs[max_subprocess:]
        except:
            continue
    return []


# Returns from a given username: an empty value, the same value, the reversed value
def get_usernames_esr(username):
    return ['', username, ''.join(reversed(username))]


# Version check utility
def check_version():
    banner = """
╔─────────────────────────────────────────────────────────────────────╗
│  ██████╗████████╗███████╗    ███████╗███╗   ██╗██╗   ██╗███╗   ███╗ │
│ ██╔════╝╚══██╔══╝██╔════╝    ██╔════╝████╗  ██║██║   ██║████╗ ████║ │
│ ██║        ██║   █████╗      █████╗  ██╔██╗ ██║██║   ██║██╔████╔██║ │
│ ██║        ██║   ██╔══╝      ██╔══╝  ██║╚██╗██║██║   ██║██║╚██╔╝██║ │
│ ╚██████╗   ██║   ██║         ███████╗██║ ╚████║╚██████╔╝██║ ╚═╝ ██║ │
│  ╚═════╝   ╚═╝   ╚═╝         ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝ │
╚─────────────────────────────────────────────────────────────────────╝
"""
    printc(banner, GREEN)

    with open('/opt/CTFEnum/CTFenum/mods/version', 'r') as file:
        current_version = file.read()
        print('[!] Version: ', end='')
        printc(current_version, GREEN)
        current_version = current_version.replace('.', '')

    online_version_url = 'https://raw.githubusercontent.com/josemlwdf/CTFEnum/main/CTFenum/mods/version'
    response = requests.get(online_version_url)
    if response:
        formatted_online_version = response.text
        online_version = formatted_online_version.replace('.', '')

    if online_version > current_version:
        printc('[*] A New version of CTF Enum is available.', GREEN)
        print('[!] GitHub version is: ', end='')
        printc(formatted_online_version, YELLOW, RED)

        answer = ''

        while (answer == ''):
            answer = input('Would you line to update now Y/N: ')
        
        if (answer.upper() == 'Y'):
            cmd = 'curl https://raw.githubusercontent.com/josemlwdf/CTFEnum/main/install.sh|bash'

            try:
                output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)

                if output:
                    print('[!] Updating...')
                    printc('[+] Update successful.', GREEN)
                    print('[!] Exiting now. Launch CTF Enum again to load the new verison.')
                    print('[!] BYE!!!')
                    sys.exit(0)
            except Exception as e:
                printc(f'[-] {e}', RED)
