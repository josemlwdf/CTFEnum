from mods.mod_utils import *
import subprocess

def handle_kerberos(ip, dns):
    filename = '/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt'
    cmd = f'nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm="{dns}",userdb={filename} {ip}'
    output = None

    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
    except:
        return

    if output:
        if 'Discovered' in output:
            result = re.findall('@n@(Discovered .+@n@@n@)', output.replace('\n', '@n@'))

            if result:
                output = result[0].replace('@n@', '\n').replace('\n\n', '')

                print_banner('88')
                print(cmd)
                printc('[+] Some usernames where found.', GREEN)
                printc(output, BLUE)
