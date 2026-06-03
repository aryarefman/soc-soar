#!/bin/bash

# Get source IP from Wazuh
IP=$1
ACTION=$2

if [ "$ACTION" = "add" ]; then
    # Silent DROP (filtered state) - tidak reply
    /sbin/iptables -I INPUT -s $IP -j DROP 2>/dev/null
    
    # Log ke file
    echo "$(date) - Blocked: $IP" >> /var/ossec/active-response/firewall-drops.log
    
elif [ "$ACTION" = "delete" ]; then
    # Remove setelah timeout
    /sbin/iptables -D INPUT -s $IP -j DROP 2>/dev/null
    echo "$(date) - Unblocked: $IP" >> /var/ossec/active-response/firewall-drops.log
fi

exit 0
