#!/usr/bin/env python3

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
from mods import mod_smb
from mods import mod_imap
from mods import mod_snmp


def arg_error():
    printc("[-] Please provide a target IP", RED)
    print(f"[!] Ex: python3 {sys.argv[0]} 192.168.0.1")
    sys.exit(1)


def main():
    check_version()

    arg = ''

    procs = []

    if len(sys.argv) != 2:
        arg_error()
    else:
        arg = sys.argv[1]
        res = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', arg)
        if not res:
            arg_error()

    ip = arg

    if ip != '127.0.0.1':
        clean_hosts(ip)

    output_dict = mod_nmap.nmap(ip)

    tcp_ports = output_dict.get('nmap_tcp_ports', '').split(',')
    udp_ports = output_dict.get('nmap_udp_ports', '').split(',')

    if not tcp_ports:
        print_separator()
        print('[*] No TCP ports open')
        sys.exit()

    nmap_detail = output_dict.get('nmap_detailed', '')

    dns = scan_for_dns(nmap_detail)
    hostname = scan_hostname(nmap_detail)

    if dns or hostname:
        clean_hosts(ip, dns)
        register_dns = [dns]
        if hostname:
            register_dns += [ hostname, f'{hostname}.{dns}' ]
        if '.' in dns: register_dns.append(dns.split('.')[0])
        mod_dns.dns_add_subdomains(ip, register_dns)

    # TCP
    for port in tcp_ports:
            # FTP
        if port == '21':
            mod_ftp.handle_ftp(ip, port, nmap_detail)
            # SSH
        elif (port == '22') or (port == '2222'):
            print_banner(port)
            print('[!] SSH')
            print('[!] You can try to bruteforce credentials using [netexec|crackmapexec|hydra].')
            print('netexec ssh $(IP) -u usernames.txt -p passwords.txt')
            # TELNET
        elif port == '23': 
            mod_telnet.handle_telnet(ip)
            # SMTP
        elif port == '25':
            mod_smtp.handle_smtp(ip)
            # FINGER
        elif port == '79':
            target=mod_finger.handle_finger(ip)
            # HTTP
        elif (port == '80') or (port == '443') or (port == '5000') or (port == '8000') or (port == '8080') or (port == '8081') or (port == '8443') or (port == '10443'):
            mod_http.handle_http(ip, port)
            # KERBEROS
        elif port == '88':
           mod_kerberos.handle_kerberos(ip, dns)
            # POP
        elif (port == '110') or (port == '995'):
            print_banner(port)
            print('[!] POP')
            print('[!] You can try to bruteforce credentials.')
            print('hydra -l username -P passwords.txt -f $(IP) pop3 -V')
            # RPD BIND
        elif port == '111':
            print_banner(port)
            print('[!] RPCBind ')
            print('[!] Reference: https://book.hacktricks.xyz/network-services-pentesting/pentesting-rpcbind')
            # IMAP
        elif (port == '143') or (port == '993'):
            mod_imap.handle_imap(ip, port)
            # SMB
        elif (port == '445'):
            mod_smb.handle_smb(ip, port)

    # UDP
    for port in udp_ports:
            # TFTP
        if port == '69':
            process = multiprocessing.Process(target=mod_tftp.handle_tftp, args=(ip,))
            procs.append(process)
            # SNMP
        if port == '161':
            process = multiprocessing.Process(target=mod_snmp.handle_snmp, args=(ip,))
            procs.append(process)     
    # DNS
    if ('53' in tcp_ports) or ('53' in udp_ports):
        process = multiprocessing.Process(target=mod_dns.handle_dns, args=(ip, dns))
        procs.append(process)
    
    procs = launch_procs(procs)


if __name__ == "__main__":
    main()
