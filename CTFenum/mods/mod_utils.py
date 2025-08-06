from colorama import init, Fore, Back, Style
import re
import requests
from os import system

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

logs_folder = 'ctfenum_logs'
system(f'mkdir {logs_folder} 2>/dev/null')

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
            results = re.findall(r'Domain: (.+)0\.', line)
            if results:
                parts = results[0].split('.')
                if len(parts) > 1:
                    dns = f'{parts[-2]}.{parts[-1]}'.strip()
                    return dns
        elif 'DNS:' in line:
            results = re.findall(r'DNS:.+\.(.+\..+)', line)
            if results:
                dns = results[0].strip()
                return dns
        elif 'DNS_Domain_Name' in line:
            results = re.findall(r'DNS_Domain_Name: (.*)\n', line)
            if results:
                dns = results[0].strip()
                return dns
        elif 'DNS_Tree_Name' in line:
            results = re.findall(r'DNS_Tree_Name: (.*)\n', line)
            if results:
                dns = results[0].strip()
                return dns
        elif ('ssl-cert' in line) and ('commonName' in line):
            results = re.findall(r'commonName=(.*)\n', line)
            if results:
                parts = results[0].split('.')
                if len(parts) > 1:
                    dns = f'{parts[-2]}.{parts[-1]}'.strip()
                    return dns
    return ''

def scan_hostname(nmap_detail):
    detail = nmap_detail.splitlines()

    for line in detail:
        if 'Host:' in line:
            results = re.findall(r'Host: (.+?);', line)
            if results:
                host = results[0].strip()
                return host
        elif 'NetBIOS:' in line:
            results = re.findall(r'NetBIOS name: (.+),', line)
            if results:
                host = results[0].strip()
                return host
        elif 'NetBIOS_Computer_Name' in line:
            results = re.findall(r'NetBIOS_Computer_Name: (.*)\n', line)
            if results:
                host = results[0].strip()
                return host
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
        except Exception:
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
        except Exception:
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

    current_version = '1.0.0'

    with open('/opt/CTFEnum/CTFenum/mods/version', 'r') as file:
        current_version = file.read()
        print('[!] Version: ', end='')
        printc(current_version, GREEN)
        current_version = current_version.replace('.', '')

    online_version_url = 'https://raw.githubusercontent.com/josemlwdf/CTFEnum/main/CTFenum/mods/version'
    online_version = current_version
    response = None
    try:
        response = requests.get(online_version_url)
    except Exception:
        pass
    if response is not None:
        formatted_online_version = response.text
        online_version = formatted_online_version.replace('.', '')

        if online_version > current_version:
            printc('[*] A New version of CTF Enum is available.', GREEN)
            print('[!] GitHub version is: ', end='')
            printc(formatted_online_version, YELLOW, RED)

            cmd = 'curl https://raw.githubusercontent.com/josemlwdf/CTFEnum/main/install.sh|bash'
            print(f'[!] {cmd}')
            printc('[-] Update as soon as possible.', RED)
            print_separator()

def log(data, cmd, target='', tool='ctfenum'):
    thislog_path = f'{logs_folder}/{target.replace(".", "-")}'
    dir_cmd = f'mkdir -p {thislog_path} 2>/dev/null'
    system(dir_cmd)
    with open(f'./{thislog_path}/{tool}.txt', 'a') as file:
        file.write('*' * 20 + '\n' + cmd + '\n\n' + data + '\n')
