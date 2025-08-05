from mods.mod_utils import print_banner, printc, BLUE
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
            print('[!] If you get creds, use this client to dump the emails: https://github.com/josemlwdf/IMAP-Mail-Dumper')
            print(f'[!] {cmd}')
            printc(output, BLUE)
    except Exception:
        return
