from mods.mod_utils import *
import subprocess
import os

def handle_kerberos(target, domain):
    # Try to bruteforce Usernames
    #enum_users(target, domain)
    # Check Kerberoast using guest creds
    check_kerberoast(target, domain)
    

def enum_users(target, domain):
    filename = '/usr/share/seclists/Usernames/Names/names.txt'
    cmd = f'nmap -Pn -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm="{domain}",userdb="{filename}" {target}'
    output = None
    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)

        if output:
            if ('Discovered' in output):
                print_banner('88')
                print('[!] KERBEROS')
                print(f'[!] {cmd}')
                printc('[+] Some usernames where found.', GREEN)
                for line in output.splitlines():
                    if domain in line:
                        user = line.split('@')[0].split(' ')[-1]
                        printc(user, BLUE)
    except Exception as e:
        if not os.path.exists(filename):
            print(f'[-] {filename} does not exist.\nPlease install seclists.')
        printc(e, RED)
        return
    

def check_kerberoast(target, domain, user='ybob317', passw='ybob317'):
    cmd = f'impacket-GetUserSPNs {domain}/{user}:{passw} -dc-ip {target}'

    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)

        if output:
            if ('ServicePrincipalName' in output):
                print_banner('88')
                print('[!] KERBEROS')
                print(f'[!] {cmd}')
                printc(f'[+] Some Kerberoastable users where found with the credentials "{user}:{passw}"', GREEN)
                for line in output.splitlines():
                    passw_last_set = re.findall('....-..-..\s.*:.*:.*\.', line)
                    if passw_last_set:
                        print(line)

    except Exception as e:
        printc(e, RED)
        return