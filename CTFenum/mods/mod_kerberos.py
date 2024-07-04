from mods.mod_utils import *
import subprocess
import os

def handle_kerberos(ip, dns):
    filename = '/usr/share/seclists/Usernames/Names/names.txt'
    cmd = f'nmap -Pn -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm="{dns}",userdb="{filename}" {ip}'
    output = None
    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)

        if output:
            if ('Discovered' in output):
                print_banner('88')
                print('[!] KERBEROS')
                print(cmd)
                printc('[+] Some usernames where found.', GREEN)
                for line in output.splitlines():
                    if dns in line:
                        user = line.split('@')[0].split(' ')[-1]
                        printc(user, BLUE)
    except Exception as e:
        if not os.path.exists(filename):
            print(f'[-] {filename} does not exist.\nPlease install seclists.')
        printc(e, RED)
        return