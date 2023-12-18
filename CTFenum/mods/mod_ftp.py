import subprocess
import multiprocessing
from ftplib import FTP
from mods.mod_utils import *


# List of common FTP users
common_ftp_users = [
    'admin','user','ftp','anonymous','test','guest','root','administrator','ftpuser','superuser','demo','manager','operator','webmaster','support','sysadmin','backup','developer','office'
]


# List of common FTP passwords
common_ftp_passwords = [
    'password','123456','admin','12345','12345678','qwerty','1234567','123456789','1234','password1','abc123','letmein','password123','changeme','123123','login','welcome','test123','ftp123'
]


def ftp_connect(server, port, username, password):
    try:
        # Connect to the FTP server on the specified port
        ftp = FTP(server)

        # Login with username and password
        ftp.login(user=username, passwd=password)

        creds_found = True
        print_separator()
        print_banner(port)
        print_separator()
        print('[!] Testing common credentials for FTP')

        # Print a message upon successful connection
        printc(f'[+] FTP Credentials {username}:{password}', GREEN)
        print_separator()

        # Perform operations (e.g., list directories, download/upload files) if needed
        # Example: List directories
        printc('[!] Listing FTP root', YELLOW)
        print_separator()
        ftp.dir()

        # Close the FTP connection
        ftp.quit()
    except:
        return


def ftp_brute(ip, port):
    procs = []
    tested_creds = []

    for username in common_ftp_users:
        for password in get_usernames_esr(username):
            current_creds = f'{username}:{password}'
            if current_creds in tested_creds:
                continue
            tested_creds.append(current_creds)

            process = multiprocessing.Process(target=ftp_connect, args=(ip, port, username, password))
            procs.append(process)
        for password in common_ftp_passwords:
            current_creds = f'{username}:{password}'
            if current_creds in tested_creds:
                continue
            tested_creds.append(current_creds)
            
            # Start processes to execute
            process = multiprocessing.Process(target=ftp_connect, args=(ip, port, username, password))
            procs.append(process)
    procs = launch_procs(procs)


def print_this_banner(port):
    print_banner(port)  
    print('''[!] If the FTP server does not lists the content, use the commands like:
    ftp:>passive
    ftp:>bin
    ftp:>ls -la''')

def handle_ftp(target, port, nmap_detail):
    if ('ftp-anon' in nmap_detail):
        print_banner(port)
        printc('[+] Server have anonymous login enabled', GREEN)
    else:        
        ftp_brute(target, port)
