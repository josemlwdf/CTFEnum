import subprocess
from mods.mod_utils import *
import multiprocessing
import socket
import os
import re


# Globals
founded = []

common_unixnames = ['root','daemon','bin','sys','sync','games','man','lp','mail','news','uucp','proxy','www-data','backup','list','irc','gnats','nobody','systemd-network','systemd-resolve','messagebus','systemd-timesync','syslog','_apt','uuidd','tcpdump','postgres','Debian-exim','polkitd','_rpc','statd','sshd','dnsmasq','msf','_gophish']


def finger_user(ip, username):
    global founded
    try:
        # Create a socket object
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Define the Finger server and port
        finger_server = (ip, 79)  # Port 79 is the default port for Finger service

        # Connect to the Finger server
        sock.connect(finger_server)

        # Send the username to request information
        sock.sendall((username + '\r\n').encode())

        # Receive and print the response
        response = sock.recv(4096).decode()
        username = re.findall('Login:(.*)Name:', response)
        if username:
            clean_username = username[0].strip()
            
            try:
                founded.index(username)
            except:
                founded.append(clean_username)
                fullname = ''
                try:
                    full_name = re.findall('Name:(.*)\n', response)
                except:
                    pass
                finger_banner(clean_username, full_name[0])
    except:
        pass
    finally:
        # Close the socket connection
        sock.close()


def finger_banner(username, full_name):
    print_banner('79')
    printc(f'[!] Username found: {username}. Full Name: {full_name}', GREEN)


def handle_finger(ip):
    procs = []
    usernames = []
    filename = '/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt'

    if not os.path.exists(filename):
        print_banner('79')
        printc('[-] Unable to bruteforce users with Finger Service', RED)
        print(f'[-] {filename} does not exist.\nPlease install seclists.')
        print('[!] Using common unix usernames to test the service.')
        usernames = common_unixnames

    with open(filename) as file:
        usernames = file.readlines()

    count = 0
    for username in usernames:        
        # Start processes to execute
        process = multiprocessing.Process(target=finger_user, args=(ip,username))
        procs.append(process)
        count += 1

        if count >= max_subprocess:
            procs = launch_procs(procs)
            count = 0
    procs = launch_procs(procs)