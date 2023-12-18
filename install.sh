#!/bin/bash
cd /opt
git clone https://github.com/josemlwdf/CTFEnum
echo 'python3 /opt/CTFEnum/CTFenum/CTFenum.py $1' > /usr/sbin/ctfenum
chmod +x /usr/sbin/ctfenum
