#!/usr/bin/env python3
import sys
import json
import urllib.request
import urllib.error
import datetime

LOG_FILE = "/var/log/soar-integrations.log"

def log(message):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_line = f"[{timestamp}] {message}\n"
    print(log_line.strip())
    try:
        with open(LOG_FILE, "a") as f:
            f.write(log_line)
    except Exception as e:
        print(f"Failed to write to log file: {e}")

def send_post(url, payload, headers):
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode('utf-8'),
        headers=headers,
        method='POST'
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            res_data = response.read().decode('utf-8')
            return True, response.status, res_data
    except urllib.error.HTTPError as e:
        return False, e.code, e.read().decode('utf-8', errors='ignore')
    except Exception as e:
        return False, 500, str(e)

def main():
    if len(sys.argv) < 5:
        log("ERROR: Insufficient arguments. Usage: soar_integrate.py <IP> <ALERT_ID> <RULE_ID> <DESCRIPTION>")
        sys.exit(1)

    ip = sys.argv[1]
    alert_id = sys.argv[2]
    rule_id = sys.argv[3]
    description = sys.argv[4]

    log(f"=== Starting SOAR Integration Trigger for DDoS Attacker IP: {ip} ===")

    # 1. Trigger Shuffle Webhook
    shuffle_url = "http://127.0.0.1:5001/webhook/ddos-alert"
    shuffle_payload = {
        "event_type": "ddos_detection",
        "attacker_ip": ip,
        "alert_id": alert_id,
        "rule_id": rule_id,
        "description": description,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z"
    }
    log(f"Sending trigger to Shuffle at {shuffle_url}...")
    ok, code, res = send_post(shuffle_url, shuffle_payload, {'Content-Type': 'application/json'})
    if ok:
        log(f"Shuffle Response [SUCCESS]: Code {code} - {res.strip()}")
    else:
        log(f"Shuffle Response [FAILED]: Code {code} - {res.strip()}")

    # 2. Trigger TheHive Case Creation
    thehive_url = "http://127.0.0.1:9000/api/case"
    thehive_payload = {
        "title": f"DDoS Attack Detected from IP {ip}",
        "description": f"Wazuh SIEM triggered alert {alert_id} (Rule {rule_id}): {description}",
        "severity": 3,
        "tags": ["DDoS", "Wazuh-SIEM", "Automated-Block"],
        "tlp": 2,
        "pap": 2
    }
    log(f"Sending incident ticket creation to TheHive at {thehive_url}...")
    # Standard TheHive APIs usually require Authorization header, we mock it here
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer MockToken1234567890'
    }
    ok, code, res = send_post(thehive_url, thehive_payload, headers)
    if ok:
        log(f"TheHive Response [SUCCESS]: Code {code} - {res.strip()}")
    else:
        log(f"TheHive Response [FAILED]: Code {code} - {res.strip()}")

    # 3. Share Threat Intel to MISP
    misp_url = "http://127.0.0.1:6666/attributes"
    misp_payload = {
        "event_id": "1002",
        "value": ip,
        "type": "ip-src",
        "category": "Network activity",
        "comment": "DDoS Attacker IP blocked by SOAR active response",
        "to_ids": True
    }
    log(f"Sending Threat Intel attribute to MISP at {misp_url}...")
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'MockMISPApiKeyValue'
    }
    ok, code, res = send_post(misp_url, misp_payload, headers)
    if ok:
        log(f"MISP Response [SUCCESS]: Code {code} - {res.strip()}")
    else:
        log(f"MISP Response [FAILED]: Code {code} - {res.strip()}")

    log("=== SOAR Integration Trigger Complete ===")

if __name__ == "__main__":
    main()
