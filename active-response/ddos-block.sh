#!/bin/bash
# Wazuh Active Response script for DDoS Auto-Mitigation and SOAR integration
# ITS - SIEM Group Task #1

LOCAL=$(dirname "$0")
cd "$LOCAL" || exit 1
cd ../ || exit 1

LOG_FILE="/var/ossec/logs/active-responses.log"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

# Read JSON input from Wazuh Manager
read -r INPUT

# Extract parameters using jq
ACTION=$(echo "$INPUT" | jq -r '.command')
IP=$(echo "$INPUT" | jq -r '.parameters.alert.data.srcip // .parameters.alert.srcip // .parameters.alert.data.src_ip // empty')
ALERT_ID=$(echo "$INPUT" | jq -r '.parameters.alert.id // "unknown"')
RULE_ID=$(echo "$INPUT" | jq -r '.parameters.alert.rule.id // "unknown"')
DESCRIPTION=$(echo "$INPUT" | jq -r '.parameters.alert.rule.description // "DDoS Attack Detected"')

echo "[$TIMESTAMP] Active Response Triggered: ACTION=$ACTION IP=$IP Rule=$RULE_ID Alert=$ALERT_ID" >> "$LOG_FILE"

# Validate IP format
if [[ ! "$IP" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    echo "[$TIMESTAMP] ERROR: Invalid or missing IP: $IP" >> "$LOG_FILE"
    exit 1
fi

# Whitelist Loopback and Target/Manager IPs
if [[ "$IP" =~ ^(127\.0\.0\.1|10\.0\.0\.4|4\.186\.24\.41)$ ]]; then
    echo "[$TIMESTAMP] SKIP: IP $IP is whitelisted/protected." >> "$LOG_FILE"
    exit 0
fi

# Execute mitigation action
if [ "$ACTION" = "add" ]; then
    # Add iptables block rule
    sudo /sbin/iptables -I INPUT -s "$IP" -j DROP
    echo "[$TIMESTAMP] BLOCKED | IP: $IP via iptables" >> "$LOG_FILE"
    logger -t "SOAR-DDoS" "AUTO-BLOCKED IP $IP"

    # Trigger SOAR Integrations (Shuffle, TheHive, MISP) in background
    sudo /var/ossec/active-response/bin/soar_integrate.py "$ACTION" "$INPUT" >> "$LOG_FILE" 2>&1 &

elif [ "$ACTION" = "delete" ]; then
    # Remove iptables block rule
    sudo /sbin/iptables -D INPUT -s "$IP" -j DROP
    echo "[$TIMESTAMP] UNBLOCKED | IP: $IP" >> "$LOG_FILE"
    logger -t "SOAR-DDoS" "AUTO-UNBLOCKED IP $IP"

    # Trigger SOAR Integrations (Shuffle, TheHive, MISP) in background
    sudo /var/ossec/active-response/bin/soar_integrate.py "$ACTION" "$INPUT" >> "$LOG_FILE" 2>&1 &
fi

exit 0
