import subprocess
from mods.mod_utils import print_banner, printc, GREEN, log
import re

def snmp_get_community(ip):
    cmd = f"msfconsole -q -x 'use scanner/snmp/snmp_login; set RHOSTS {ip}; set ANONYMOUS_LOGIN true; set BLANK_PASSWORDS true; set STOP_ON_SUCCESS true; set VERBOSE false; set VERSION all; run; exit'|grep '+'"
    community = 'public'
    output = None

    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)

        if output:
            community_array = re.findall(r'Login Successful: (.*) \(Access?', output)
            if community_array:
                community = community_array[0]
                print_banner('161')
                print('[!] SNMP')
                print(f'[!] {cmd}')
                printc(f'[+] Community password: {community}', GREEN)
                print(output)

                log(output, cmd, ip, 'msfconsole')
    except Exception:
        pass

    return community


def snmp_enum(ip):
    cmd = f"nmap {ip} -sU -T5 -p161 -sV --script='snmp* and not snmp-brute'"
    output = None

    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)

        if output:
            print_banner('161')
            print('[!] SNMP')
            print(f'[!] {cmd}')
            result = re.findall(r'@n@(PORT .+@n@@n@)', output.replace('\n', '@n@'))
            if result:
                print(result[0].replace('@n@', '\n').replace('\n\n', ''))

                log(output, cmd, ip, 'nmap')
    except Exception:
        return


def snmp_get_strings(ip, community):
    versions = ['1', '2c']
    options = ['', 'NET-SNMP-EXTEND-MIB::nsExtendObjects']

    for version in versions:
        for option in options:
            cmd = f"snmpwalk -Oa -c {community} -v {version} -t 10 {ip} {option}"

            if option == '':
                cmd = f"snmpwalk -Oa -c {community} -v {version} -t 10 {ip} | grep -i 'STRING'"

            output = None

            try:
                output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)

                if output:
                    print_banner('161')
                    print('[!] SNMP')
                    print(f'[!] {cmd}')
                    print(output)

                    log(output, cmd, ip, 'snmpwalk')
            except Exception:
                return


def handle_snmp(ip):
    #printc('snmp', RED)

    community = snmp_get_community(ip)
    snmp_enum(ip)
    snmp_get_strings(ip, community)
