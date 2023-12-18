import subprocess
import multiprocessing
import re
from mods.mod_utils import *


def nmap_udp(ip, output_dict):
    cmd = f'nmap -Pn -n -T4 -sU --open -p53,69,161,11211 {ip}'
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
        return


def nmap_tcp(ip, output_dict):
    cmd = f'nmap -Pn -T4 -n -p- {ip}'

    try:
        output = subprocess.check_output(cmd.split(' '), stderr=subprocess.STDOUT, universal_newlines=True)
    except:
        return

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


def nmap_detailed_tcp_scan(ip, ports, output_dict):
    test_ports = ports.split(',')
    if ('23' in ports) or ('25' in ports):
        printc('[!] I have identified some services that slows Nmap', YELLOW)
        printc('[!] Some of these ports will be removed from the detailed scan', YELLOW)
        printc('[!] This scan could still take some time. Be patient', YELLOW)
        test_ports.remove('23').remove('25')
        ports = ','.join(test_ports)

    cmd = f'nmap -T5 -n -Pn -sCV -p{ports} {ip}'

    try:
        output = subprocess.check_output(cmd.split(' '), stderr=subprocess.STDOUT, universal_newlines=True)
    except:
        return

    result = re.findall('@n@(PORT .+@n@@n@)', output.replace('\n', '@n@'))

    if result:
        output = result[0].replace('@n@', '\n').replace('\n\n', '')

        print_separator()
        print('NMAP TCP OUTPUT:')
        print(f'[!] {cmd}')
        print(output)

    output_dict['nmap_detailed'] = output


def nmap(ip):
    print_separator()
    print('[!] Checking open ports')
    # Get open ports on target
    output_dict = multiprocessing.Manager().dict()

    procs = []

    # Start processes to execute the nmap commands
    process = multiprocessing.Process(target=nmap_tcp, args=(ip, output_dict))
    procs.append(process)

    process = multiprocessing.Process(target=nmap_udp, args=(ip, output_dict))
    procs.append(process)

    procs = launch_procs(procs)

    print_separator()
    print('[!] Generating Nmap output')

    tcp_ports = output_dict.get('nmap_tcp_ports', '')

    if tcp_ports:
        process = multiprocessing.Process(target=nmap_detailed_tcp_scan, args=(ip, tcp_ports, output_dict))
        procs.append(process)

    udp_ports = output_dict.get('nmap_udp_ports', '')

    procs = launch_procs(procs)

    return output_dict
