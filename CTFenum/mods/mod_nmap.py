import subprocess
import re
from mods.mod_utils import printc, print_separator, log, YELLOW

# Add 2 new lines before and after the nmap outputs tot he debug files
debug = False

def nmap_udp(ip, output_dict):
    cmd = f'nmap -F -T4 -sU -Pn --max-parallelism 512 --min-rtt-timeout 50ms --max-retries 1 -n --open {ip}'
    output = ''

    try:
        output = subprocess.check_output(cmd.split(' '), stderr=subprocess.STDOUT, universal_newlines=True)
        ports = ''

        result = re.findall(r'@n@(PORT .+@n@@n@)', output.replace('\n', '@n@'))

        if result:
            output = result[0].replace('@n@', '\n').replace('\n\n', '')

            print_separator()
            printc('OPEN UDP PORTS:', YELLOW)
            print(f'[!] {cmd}')
            print(output)

            log(output, cmd, ip, 'nmap')

            ports = re.findall(r'@n@([0-9]+)/', result[0])
            ports = ','.join(ports)

            output_dict['nmap_udp_ports'] = ports
    except Exception:
        pass
    return output_dict


def nmap_tcp(ip, output_dict):
    cmd = f'nmap -Pn -T4 -n -p- {ip}'
    output = ''

    try:
        if not debug:
            output = subprocess.check_output(cmd.split(' '), stderr=subprocess.STDOUT, universal_newlines=True)
        else:
            with open('nmap.txt') as file:
                output = file.read()
        ports = ''

        result = re.findall(r'@n@(PORT .+@n@@n@)', output.replace('\n', '@n@'))

        if result:
            output = result[0].replace('@n@', '\n').replace('\n\n', '')

            print_separator()
            printc('OPEN TCP PORTS:', YELLOW)
            print(f'[!] {cmd}')
            print(output)

            log(output, cmd, ip, 'nmap')

            ports = re.findall(r'@n@([0-9]+)/', result[0])
            ports = ','.join(ports)

            output_dict['nmap_tcp_ports'] = ports
    except Exception:
        #print(e)
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
                except Exception:
                    continue
    ports = ','.join(test_ports)

    cmd = f'nmap -T5 -n -Pn -sCV -p{ports} {ip}'

    try:
        if not debug:
            output = subprocess.check_output(cmd.split(' '), stderr=subprocess.STDOUT, universal_newlines=True)
        else:
            with open('nmap2.txt') as file:
                output = file.read()

        result = re.findall(r'@n@(PORT .+@n@@n@)', output.replace('\n', '@n@'))

        if result:
            output = result[0].replace('@n@', '\n').replace('\n\n', '')

            print_separator()
            print('NMAP TCP OUTPUT:')
            print(f'[!] {cmd}')
            print(output)

            log(output, cmd, ip, 'nmap')

        output_dict['nmap_detailed'] = output
    except Exception:
        pass
    return output_dict


def nmap(ip):
    #printc('nmap', RED)
    print_separator()
    print('[!] Checking open ports')
    # Get open ports on target
    output_dict = {}

    # Start processes to execute the nmap commands
    output_dict = nmap_tcp(ip, output_dict)
    if not debug:
        output_dict = nmap_udp(ip, output_dict)

    print_separator()
    print('[!] Generating Nmap output')

    tcp_ports = output_dict.get('nmap_tcp_ports', '')

    if tcp_ports:
        output_dict = nmap_detailed_tcp_scan(ip, tcp_ports, output_dict)

    return output_dict
