import subprocess
from mods.mod_utils import *

def handle_telnet(ip):
    cmd = f'nmap -n -T5 -sV -Pn --script=telnet-ntlm-info -p 23 {ip}'
    
    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
        if output:
            result = re.findall('@n@(PORT .+@n@@n@)', output.replace('\n', '@n@'))[0]    
            if result:
                print_banner('23')
                print(f'[!] {cmd}')
                print(result)
    except:
        return