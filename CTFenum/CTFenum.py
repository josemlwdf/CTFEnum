import subprocess
import multiprocessing
import sys
import re
from mods.mod_utils import *
from mods import mod_nmap
from mods import mod_ftp
from mods import mod_telnet
from mods import mod_smtp
from mods import mod_dns
from mods import mod_tftp
from mods import mod_finger
from mods import mod_http
from mods import mod_kerberos


def main():
    if len(sys.argv) != 2:
        print("Please provide a string argument")
        sys.exit(1)

    ip = sys.argv[1]

    output_dict = mod_nmap.nmap(ip)

    tcp_ports = output_dict.get('nmap_tcp_ports', '').split(',')
    udp_ports = output_dict.get('nmap_udp_ports', '').split(',')

    if not tcp_ports:
        print_separator()
        print('[*] No TCP ports open')
        sys.exit()

    nmap_detail = output_dict.get('nmap_detailed', '')

    procs = []

    dns = ''

    # TCP
    for port in tcp_ports:
        if port == '21':
            process = multiprocessing.Process(target=mod_ftp.handle_ftp, args=(ip, port, nmap_detail))
            procs.append(process)
        if port == '22':
            print_separator()
            printc('[!] Attacking port 22', YELLOW) 
            print('[!] You can try to bruteforce credentials.')
            print("crackmapexec ssh -u usernames.txt -p passwords.txt $(IP) | grep -E '\+|\*'")
        if port == '23': 
            process = multiprocessing.Process(target=mod_telnet.handle_telnet, args=(ip,))
            procs.append(process)
        if port == '25':
            process = multiprocessing.Process(target=mod_smtp.handle_smtp, args=(ip,))
            procs.append(process)
        if port == '79':
            process = multiprocessing.Process(target=mod_finger.handle_finger, args=(ip,))
            procs.append(process)
        if (port == '80') or (port == '443') or (port == '5000') or (port == '8000') or (port == '8080') or (port == '8081') or (port == '8443'):
            process = multiprocessing.Process(target=mod_http.handle_http, args=(ip, port))
            procs.append(process)
        if port == '88':
            process = multiprocessing.Process(target=mod_kerberos.handle_kerberos, args=(ip,))
            procs.append(process)


    # UDP
    for port in udp_ports:
        if port == '69':
            process = multiprocessing.Process(target=mod_tftp.handle_tftp, args=(ip,))
            procs.append(process)
        
    if ('53' in tcp_ports) or ('53' in udp_ports):
        process = multiprocessing.Process(target=mod_dns.handle_dns, args=(ip, dns))
        procs.append(process)
    
    procs = launch_procs(procs)



if __name__ == "__main__":
    mod_http.handle_http('192.168.152.130', '443')