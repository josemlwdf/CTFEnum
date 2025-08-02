import subprocess
from mods.mod_utils import print_banner

def handle_nfs(ip, port):
    print_banner(port)
    print('[!] NFS')
    print('[*] Running Nmap NFS scripts...')
    try:
        # Run nmap with nfs scripts on ports 111 and 2049
        cmd = [
            'sudo', 'nmap', '--script', 'nfs*', '-sV', '-p111,2049', ip
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        print(result.stdout)
        if result.stderr:
            print('[!] Nmap stderr:', result.stderr)
    except Exception as e:
        print(f'[!] Error running Nmap NFS scripts: {e}')
