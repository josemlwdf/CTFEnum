import subprocess
from mods.mod_utils import *

def handle_smtp(ip):
    cmd = f'nmap -n -T5 -Pn --script="*smtp* and not brute" -p 25 {ip}'
    
    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
        if output:
            result = re.findall('@n@(PORT .+@n@@n@)', output.replace('\n', '@n@'))[0]    
            if result:
                print_separator()
                printc('[!] Attacking port 25', YELLOW) 
                print(f'[!] {cmd}')
                print(result)
    except:
        return