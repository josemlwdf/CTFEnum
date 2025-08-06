import subprocess
from mods.mod_utils import print_banner, log

def handle_smtp(ip):
    cmd = f'msfconsole -q -x "use auxiliary/scanner/smtp/smtp_enum;set RHOSTS {ip};set UNIXONLY false;set USER_FILE /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt;run;exit;"'
    output = None

    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
        if output:
            print_banner('25')
            print('[!] SMTP')
            print(f'[!] {cmd}')
            print(output)
            log(output, cmd, ip, 'msfconsole')
    except Exception:
        return
