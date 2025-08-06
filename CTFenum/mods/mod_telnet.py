import subprocess
from mods.mod_utils import re, print_banner, log

def handle_telnet(ip):
    cmd = f'nmap -n -T5 -sV -Pn --script=telnet-ntlm-info -p 23 {ip}'
    output = None

    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)

        if output:
            result = re.findall(r'@n@(PORT .+@n@@n@)', output.replace('\n', '@n@'))[0]
            if result:
                print_banner('23')
                print('[!] TELNET')
                print(f'[!] {cmd}')
                print(result)

                log(output, cmd, ip, 'nmap')
    except Exception:
        return
