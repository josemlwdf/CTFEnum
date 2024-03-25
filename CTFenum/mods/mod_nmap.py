import subprocess
import re
from mods.mod_utils import *


def nmap_udp(ip, output_dict):
    cmd = f'nmap -F -T4 -sU -Pn --max-parallelism 512 --min-rtt-timeout 50ms --max-retries 1 -n --open {ip}'
    output = ''

    try:
        output = subprocess.check_output(cmd.split(' '), stderr=subprocess.STDOUT, universal_newlines=True)
        ports = ''

        result = re.findall('@n@(PORT .+@n@@n@)', output.replace('\n', '@n@'))

        if result:
            output = result[0].replace('@n@', '\n').replace('\n\n', '')

            print_separator()
            printc('OPEN UDP PORTS:', YELLOW)
            print(f'[!] {cmd}')
            print(output)

            ports = re.findall('@n@([0-9]+)/', result[0])
            ports = ','.join(ports)

            output_dict['nmap_udp_ports'] = ports
    except:
        pass        
    return output_dict


def nmap_tcp(ip, output_dict):
    cmd = f'nmap -Pn -T3 -n -p- {ip}'
    output = ''

    try:
        output = subprocess.check_output(cmd.split(' '), stderr=subprocess.STDOUT, universal_newlines=True)   
        ports = ''

        result = re.findall('@n@(PORT .+@n@@n@)', output.replace('\n', '@n@'))

        if result:
            output = result[0].replace('@n@', '\n').replace('\n\n', '')

            print_separator()
            printc('OPEN TCP PORTS:', YELLOW)
            print(f'[!] {cmd}')
            print(output)

            ports = re.findall('@n@([0-9]+)/', result[0])
            ports = ','.join(ports)
        
            output_dict['nmap_tcp_ports'] = ports
    except:
        pass    
    return output_dict


def nmap_detailed_tcp_scan(ip, ports, output_dict):
    blacklisted = ['23', '25']
    test_ports = ports.split(',')

    for blacklisted_port in blacklisted:
        for port in test_ports:
            if (blacklisted_port == port):
                printc('[!] I have identified some services that slows Nmap', YELLOW)
                printc(f'[!] Some of these ports will be removed from the detailed scan: {blacklisted_port}', YELLOW)
                printc('[!] This scan could still take some time. Be patient', YELLOW)
                try:
                    test_ports.remove(blacklisted_port)
                except:
                    continue
    ports = ','.join(test_ports)

    cmd = f'nmap -T5 -n -Pn -sCV -p{ports} {ip}'

    try:
        output = subprocess.check_output(cmd.split(' '), stderr=subprocess.STDOUT, universal_newlines=True)
    
        result = re.findall('@n@(PORT .+@n@@n@)', output.replace('\n', '@n@'))

        if result:
            output = result[0].replace('@n@', '\n').replace('\n\n', '')

            print_separator()
            print('NMAP TCP OUTPUT:')
            print(f'[!] {cmd}')
            print(output)

        output_dict['nmap_detailed'] = output
    except:
        pass
    return output_dict


def nmap(ip):
    print_separator()
    print('[!] Checking open ports')
    # Get open ports on target
    output_dict = {}

    # Start processes to execute the nmap commands
    output_dict = nmap_tcp(ip, output_dict)   
    output_dict = nmap_udp(ip, output_dict)

    print_separator()
    print('[!] Generating Nmap output')

    tcp_ports = output_dict.get('nmap_tcp_ports', '')

    if tcp_ports:
        output_dict = nmap_detailed_tcp_scan(ip, tcp_ports, output_dict)

    #udp_ports = output_dict.get('nmap_udp_ports', '')

    return output_dict
