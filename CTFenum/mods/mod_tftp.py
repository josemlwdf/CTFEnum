import subprocess
from mods.mod_utils import *

def handle_tftp(ip):
    cmd = f'msfconsole -q -x "use admin/tftp/tftp_transfer_util;set rhost {ip};set filename /etc/hostname;run;exit;"'
    output = None
    
    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
        
        if 'WRQ accepted, sending the file' in output:
            print_banner('69 UDP')
            print('[!] TFTP')
            printc('[+] TFTP server allows PUT files.', GREEN)
            print('[!] You can also try to bruteforce filenames to download.')
    except:
        return