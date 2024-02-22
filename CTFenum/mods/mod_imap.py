from mods.mod_utils import *
import subprocess

def handle_imap(ip, port):
    cmd = f"msfconsole -q -x 'use auxiliary/scanner/imap/imap_version; set RHOSTS {ip}; set RPORT {port}; run; exit'"
    output = None

    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)

        if output:
            print_banner(port)
            print('[!] IMAP ')
            print('[!] https://book.hacktricks.xyz/network-services-pentesting/pentesting-imap')
            print(cmd)
            printc(output, BLUE)
    except:
        return