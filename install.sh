#!/bin/bash
set -euo pipefail

# Add Kali repositories
echo -e "deb http://http.kali.org/kali kali-rolling main non-free contrib\ndeb-src http://http.kali.org/kali kali-rolling main non-free contrib" | sudo tee -a /etc/apt/sources.list

# Add Kali keyrings
cd /tmp && wget http://http.kali.org/kali/pool/main/k/kali-archive-keyring/kali-archive-keyring_$(date | awk '{print $7}').1_all.deb && sudo apt install ./kali-archive-keyring*.deb && rm ./kali-archive-keyring*.deb

# Update the packages list
sudo apt update

# Determine which pip to use
if which pip3 &>/dev/null; then
    PIP_CMD="pip3"
else
    echo "[!] pip3 not found, installing python3-pip..."
    sudo apt install -y python3-pip
    PIP_CMD="pip3"
fi

# Function to check if a command exists
command_exists() {
    which "$1" >/dev/null 2>&1
}

sudo rm -rf /opt/CTFEnum

# Detect WSL
PIP_EXTRA_ARGS=""
if grep -qi microsoft /proc/sys/kernel/osrelease || uname -r | grep -i microsoft; then
    echo "[*] Detected WSL - adding --break-system-packages to pip install"
    PIP_EXTRA_ARGS="--break-system-packages"
fi

sudo $PIP_CMD install --upgrade colorama $PIP_EXTRA_ARGS

# Install or fallback via Snap/Git
install_tool() {
    local bin="$1" pkg="$2" snap="$3" git_repo="$4" git_dest="$5"
    if ! command_exists "$bin"; then
        echo "[*] Installing $bin..."
        if apt-cache show "$pkg" &>/dev/null; then
            sudo apt install -y "$pkg"
        elif command_exists snap && [ -n "$snap" ]; then
            sudo snap install "$snap"
        elif [ -n "$git_repo" ]; then
            sudo git clone "$git_repo" "$git_dest"
        else
            echo "[!] No install method for $bin"
        fi
    fi
}

# git
install_tool git git "" "" ""
# seclists
install_tool seclists seclists "" https://github.com/danielmiessler/SecLists.git /usr/share/SecLists
# nmap
install_tool nmap nmap "" "" ""
# gobuster
install_tool gobuster gobuster "" "" ""
# sntp
install_tool sntp sntp "" "" ""
# john
install_tool john john "" "" ""
# impacket
install_tool impacket-GetUserSPNs impacket-scripts "" https://github.com/fortra/impacket.git /opt/impacket

# Check and install feroxbuster
if ! command_exists feroxbuster; then
    echo "[*] Installing feroxbuster..."
    if apt-cache show feroxbuster &>/dev/null; then
        sudo apt install -y feroxbuster
    else
        curl -sL https://github.com/epi052/feroxbuster/releases/latest/download/feroxbuster_amd64.deb.zip -o feroxbuster.deb.zip
        unzip -o feroxbuster.deb.zip
        sudo apt install -y ./feroxbuster_*_amd64.deb
        rm -f feroxbuster.deb.zip feroxbuster_*_amd64.deb
    fi
fi

# metasploit
install_tool msfconsole metasploit-framework "" "" ""
# dig (dnsutils)
install_tool dig dnsutils "" "" ""
# snmpwalk (snmp)
install_tool snmpwalk snmp "" "" ""

# Check and install ldapdomaindump
if ! command_exists ldapdomaindump; then
    echo "Installing ldapdomaindump..."
    sudo $PIP_CMD install ldapdomaindump
fi

# Clone CTFEnum repository and set up ctfenum command
if [ ! -d "/opt/CTFEnum" ]; then
    echo "Cloning CTFEnum repository..."
    sudo git clone https://github.com/josemlwdf/CTFEnum /opt/CTFEnum
    sudo chown -R "$(id -u):$(id -g)" /opt/CTFEnum
    git config --global --add safe.directory /opt/CTFEnum
fi

# Create ctfenum command
if [ ! -f "/usr/sbin/ctfenum" ]; then
    echo "Setting up ctfenum command..."
    echo '#!/bin/bash' | sudo tee /usr/sbin/ctfenum 2>/dev/null
    echo 'sudo python3 /opt/CTFEnum/CTFenum/CTFenum.py "$1"' | sudo tee -a /usr/sbin/ctfenum 2>/dev/null
    sudo chmod +x /usr/sbin/ctfenum;
fi
