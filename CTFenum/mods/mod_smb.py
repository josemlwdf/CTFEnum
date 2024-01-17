import subprocess
import re
from mods.mod_utils import *

smb_users = ["","guest","admin","user","manager","supervisor","administrator","test","it","backup","lab","demo","smb"]
smb_passwords = ["","password","admin","administrator","backup","test","lab","demo"]


def export_wordlists():
    with open('smb_users.txt', 'w') as file:
        file.write('\n'.join(smb_users))
        file.close()
    
    with open('smb_pass.txt', 'w') as file:
        file.write('\n'.join(smb_passwords))
        file.close()


def handle_smb(target):
    cmd = f'msfconsole -q -x "use scanner/smb/smb_login;set BLANK_PASSWORDS true;set ANONYMOUS_LOGIN true;set rhosts {target};set USER_AS_PASS true;set STOP_ON_SUCCESS true;set VERBOSE false;set PASS_FILE $(pwd)/smb_pass.txt; set USER_FILE $(pwd)/smb_users.txt;run;exit;"'

    export_wordlists()

    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
    except:
        return

    if output:
        lines = output.splitlines()
        for line in lines:
            if ('[+]' in line) and ('Success' in line):
                print_banner('445')
                print('[!]', cmd)
                printc('[+] Creds Found!!!', GREEN)
                print('')
                print(line)

                res = re.findall("Success: '(.*)'", line)

                user = ''
                passw = ''

                if res:
                    domain = res[0].split('\\')[0]
                    creds = res[0].split('\\')[1]
                    user = creds.split(':')[0]
                    passw = creds.split(':')[1]

                cmd = f'msfconsole -q -x "use scanner/smb/smb_enumshares;set rhosts {target};set LogSpider 0;set MaxDepth 0;set SMBPass {passw};set SMBUser {user};set ShowFiles true;set SpiderShares true;run;exit;"'

                try:
                    output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
                except:
                    return

                if output:
                    print_banner('445')
                    print('[!]', cmd)
                    print('[!] Enumerating Shares.')
                    print('')
                    print(output)

                cmd = f'msfconsole -q -x "use scanner/smb/smb_lookupsid;set rhosts {target};set MinRID 1000;set MaxRID 5000;set SMBUser {user};set SMBPass {passw};set THREADS 10;set SMBDomain {domain};run;exit;"'

                try:
                    output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
                except:
                    return

                if output:
                    print_banner('445')
                    print('[!]', cmd)
                    print('[!] RID Cycling Attack to get Usernames')
                    print('')
                    print(output)
                
                break