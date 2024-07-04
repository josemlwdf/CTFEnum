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
    print(f"[-] Ex: python3 {sys.argv[0]} 192.168.0.1")
    sys.exit(1)


def main():
    arg = ''

    if len(sys.argv) != 2:
        arg_error()
    else:
        arg = sys.argv[1]
        res = re.findall('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', arg)
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

    procs = []

    dns = scan_for_dns(nmap_detail)

    if dns:
        clean_hosts(ip, dns)

    # TCP
    for port in tcp_ports:
            # FTP
        if port == '21':
            process = multiprocessing.Process(target=mod_ftp.handle_ftp, args=(ip, port, nmap_detail))
            procs.append(process)
            # SSH
        elif (port == '22') or (port == '2222'):
            print_banner(port)
            print('[!] SSH')
            print('[!] You can try to bruteforce credentials using [netexec|crackmapexec|hydra].')
            print("netexec ssh $(IP) -u usernames.txt -p passwords.txt | grep -v fail")
            # TELNET
        elif port == '23': 
            process = multiprocessing.Process(target=mod_telnet.handle_telnet, args=(ip,))
            procs.append(process)
            # SMTP
        elif port == '25':
            process = multiprocessing.Process(target=mod_smtp.handle_smtp, args=(ip,))
            procs.append(process)
            # FINGER
        elif port == '79':
            process = multiprocessing.Process(target=mod_finger.handle_finger, args=(ip,))
            procs.append(process)
            # HTTP
        elif (port == '80') or (port == '443') or (port == '5000') or (port == '8000') or (port == '8080') or (port == '8081') or (port == '8443'):
            procs = launch_procs(procs)
            process = multiprocessing.Process(target=mod_http.handle_http, args=(ip, port))
            procs.append(process)
            procs = launch_procs(procs)
            # KERBEROS
        elif port == '88':
            process = multiprocessing.Process(target=mod_kerberos.handle_kerberos, args=(ip, dns))
            procs.append(process)
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
            process = multiprocessing.Process(target=mod_imap.handle_imap, args=(ip, port))
            procs.append(process)
            # SMB
        elif (port == '445'):
            process = multiprocessing.Process(target=mod_smb.handle_smb, args=(ip, port))
            procs.append(process)

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