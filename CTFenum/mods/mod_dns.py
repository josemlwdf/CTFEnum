import subprocess
from mods.mod_utils import *


def dns_print_banner():
    print_banner('53')
    print('[!] DNS')
    print('[+] Subdomains added to /etc/hosts:')
    print_separator()


def dns_add_subdomains(ip, subdomains):
    if len(subdomains) < 1:
        return

    with open('/etc/hosts', 'r') as file:
        data = file.readlines()

    line_to_delete = []

    updated_line = ''

    for line in data:
        if len(line) < 5:
            line_to_delete.append(line)
        for subd in subdomains:
            if subd in line:
                line_to_delete.append(line)
                break
        if ip in line:
            line_to_delete.append(line)
            continue
    
    subs_line = []

    for line in line_to_delete:
        try:
            data.remove(line)
            if len(line) >= 5:
                subs_line.extend(line.split(' ')[1:])
        except:
            continue
    for subd in subdomains:
        if not subd in subs_line:
            subs_line.append(subd)
    subs = " ".join(set(subs_line)).replace('\n', ' ')
    updated_line = f'\n{ip} {subs}\n'
    data.append(updated_line)

    with open('/etc/hosts', 'w') as file:
        file.write(''.join(data))


def handle_dns(ip, dns=None):
    #printc('dns', RED)
    
    if not dns:
        dns_print_banner()
        printc('[-] None', RED)
        print('[!] If you find a FQDN you can use this command to look for other subdomains:')
        print(f'[!] dig axfr @{ip} your.domain.tld')

    cmd_dns = f'dig axfr @{ip} {dns}'

    try:
        output = subprocess.check_output(cmd_dns, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)

        if output:
            if 'SERVER:' in output:
                subdomains = set()

                # Split the output by lines and iterate through each line
                for line in output.splitlines():
                    # Check if the line contains a subdomain
                    if dns in line:
                        parts = line.split()
                        # Extract the subdomain and add it to the set of unique subdomains
                        subdomain = parts[0].rstrip('.')

                        if dns in subdomain:
                            subdomains.add(subdomain)

                if len(subdomains) > 0:
                    try:
                        dns_add_subdomains(ip, subdomains)
                        dns_print_banner()
                        print(f'[!] {cmd_dns}')
                        data = '\n'.join(subdomains)
                        printc(data, GREEN)

                        log(data, cmd_dns, ip, 'dig')
                    except:
                        return
    except:
        return