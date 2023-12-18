#!/bin/bash
cd /opt
sudo git clone https://github.com/josemlwdf/CTFEnum
sudo echo 'python3 /opt/CTFEnum/CTFenum/CTFenum.py $1' > /usr/sbin/ctfenum
sudo chmod +x /usr/sbin/ctfenum

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check and install seclists
if ! command_exists seclists; then
    echo "Installing seclists..."
    sudo apt install seclists -y
fi

# Check and install nmap
if ! command_exists nmap; then
    echo "Installing nmap..."
    sudo apt install nmap -y
fi

# Check and install gobuster
if ! command_exists gobuster; then
    echo "Installing gobuster..."
    sudo apt install gobuster -y
fi

# Check and install Metasploit
if ! command_exists msfconsole; then
    echo "Installing Metasploit..."
    sudo apt install msfconsole -y
fi

# Check and install dig (part of dnsutils)
if ! command_exists dig; then
    echo "Installing dnsutils (includes dig)..."
    sudo apt install dig -y
fi
