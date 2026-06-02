#!/usr/bin/env python3
"""
SOAR Integration Gateway Script
ITS - SIEM & SOAR Group Task #1
Enterprise-grade integration with Parallel Execution (Multithreading),
Rotating File Handlers, and rich metadata parsing.
"""

import sys
import json
import urllib.request
import urllib.error
import datetime
import logging
from logging.handlers import RotatingFileHandler
import os
import concurrent.futures

# Default Config Paths
CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "soar_config.json")
DEFAULT_LOG_FILE = "/var/log/soar-integrations.log"

def load_config():
    try:
        if os.path.exists(CONFIG_PATH):
            with open(CONFIG_PATH, 'r') as f:
                return json.load(f)
    except Exception as e:
        print(f"Warning: Failed to load config from {CONFIG_PATH}: {e}. Using defaults.")
    return {}

def setup_logging(config):
    log_conf = config.get("logging", {})
    log_file = log_conf.get("file", DEFAULT_LOG_FILE)
    log_level_str = log_conf.get("level", "INFO").upper()
    
    level = getattr(logging, log_level_str, logging.INFO)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    
    # Remove existing handlers to avoid duplicates
    root_logger.handlers = []
    
    # Format for logs
    log_formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] [SOAR-GATEWAY] %(message)s')
    
    # Setup RotatingFileHandler (10MB per file, max 5 files)
    try:
        file_handler = RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=5)
        file_handler.setFormatter(log_formatter)
        root_logger.addHandler(file_handler)
    except Exception as e:
        # If unable to write to the main log file, fallback to current dir or stderr
        fallback_log = "soar-integrations-fallback.log"
        try:
            file_handler = RotatingFileHandler(fallback_log, maxBytes=2*1024*1024, backupCount=2)
            file_handler.setFormatter(log_formatter)
            root_logger.addHandler(file_handler)
            print(f"Warning: Unable to write to {log_file}. Logging to {fallback_log} instead. Error: {e}")
        except Exception:
            pass
            
    # Always log to stdout/stderr for Wazuh Active Response capture
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(log_formatter)
    root_logger.addHandler(stream_handler)

def send_http_request(url, payload, headers, timeout=5, retries=2):
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode('utf-8'),
        headers=headers,
        method='POST'
    )
    for attempt in range(1, retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                return True, response.status, response.read().decode('utf-8')
        except urllib.error.HTTPError as e:
            err_msg = e.read().decode('utf-8', errors='ignore')
            logging.error(f"HTTP Error {e.code} on attempt {attempt} for {url}: {err_msg}")
            if attempt == retries:
                return False, e.code, err_msg
        except Exception as e:
            logging.error(f"Connection error on attempt {attempt} for {url}: {e}")
            if attempt == retries:
                return False, 500, str(e)
    return False, 500, "Max retries reached"

def get_utc_timestamp():
    if sys.version_info >= (3, 11):
        return datetime.datetime.now(datetime.timezone.utc).isoformat()
    return datetime.datetime.utcnow().isoformat() + "Z"

def trigger_shuffle(config, action, ip, alert_id, rule_id, description, agent_name, rule_level):
    shuffle_conf = config.get("shuffle", {})
    if not shuffle_conf.get("enabled", True):
        return

    url = shuffle_conf.get("url", "http://127.0.0.1:5001/webhook/ddos-alert")
    timeout = shuffle_conf.get("timeout", 5)

    payload = {
        "event_type": "ddos_mitigation",
        "action": action,
        "attacker_ip": ip,
        "alert_id": alert_id,
        "rule_id": rule_id,
        "rule_level": rule_level,
        "agent_name": agent_name,
        "description": description,
        "timestamp": get_utc_timestamp()
    }

    logging.info(f"Triggering Shuffle webhook for action: {action}...")
    headers = {'Content-Type': 'application/json'}
    ok, code, res = send_http_request(url, payload, headers, timeout=timeout)
    if ok:
        logging.info(f"Shuffle Response [SUCCESS]: Code {code}")
    else:
        logging.error(f"Shuffle Response [FAILED]: Code {code}")

def trigger_thehive(config, action, ip, alert_id, rule_id, description, agent_name, rule_level):
    thehive_conf = config.get("thehive", {})
    if not thehive_conf.get("enabled", True):
        return

    url = thehive_conf.get("url", "http://127.0.0.1:9000/api/case")
    token = thehive_conf.get("api_key", "Bearer MockToken1234567890")
    timeout = thehive_conf.get("timeout", 5)

    headers = {
        'Content-Type': 'application/json',
        'Authorization': token
    }

    if action == "add":
        payload = {
            "title": f"DDoS Attack Blocked from IP {ip}",
            "description": (
                f"Wazuh SIEM detected a DDoS attack (Rule {rule_id}, Level {rule_level}) "
                f"targeting Agent '{agent_name}'. Alert ID: {alert_id}.\n\n"
                f"Alert Description: {description}\n\n"
                f"Mitigation: Attacker IP dropped via iptables on the target machine."
            ),
            "severity": 3 if (rule_level.isdigit() and int(rule_level) >= 12) else 2,
            "tags": ["DDoS", "Wazuh-SIEM", f"Agent:{agent_name}", f"Rule:{rule_id}", "Automated-Block"],
            "tlp": 2,
            "pap": 2
        }
        logging.info(f"Creating incident case in TheHive for IP: {ip}...")
        ok, code, res = send_http_request(url, payload, headers, timeout=timeout)
    else:
        # Action is delete (timeout expired, unblocked IP)
        payload = {
            "title": f"DDoS Attack Case Update - IP {ip} Unblocked",
            "description": (
                f"DDoS Active Response block timeout expired for IP {ip} "
                f"on Agent '{agent_name}'. Firewall rule removed."
            ),
            "severity": 1,
            "tags": ["DDoS", f"Agent:{agent_name}", "Timeout-Expired", "Unblocked"],
            "tlp": 2,
            "pap": 2
        }
        logging.info(f"Updating incident case in TheHive (Unblock IP {ip})...")
        ok, code, res = send_http_request(url, payload, headers, timeout=timeout)

    if ok:
        logging.info(f"TheHive Response [SUCCESS]: Code {code}")
    else:
        logging.error(f"TheHive Response [FAILED]: Code {code}")

def trigger_misp(config, action, ip, alert_id, rule_id, description, agent_name, rule_level):
    misp_conf = config.get("misp", {})
    if not misp_conf.get("enabled", True):
        return

    url = misp_conf.get("url", "http://127.0.0.1:6666/attributes")
    token = misp_conf.get("api_key", "MockMISPApiKeyValue")
    timeout = misp_conf.get("timeout", 5)

    headers = {
        'Content-Type': 'application/json',
        'Authorization': token
    }

    payload = {
        "event_id": "1002",
        "value": ip,
        "type": "ip-src",
        "category": "Network activity",
        "comment": f"DDoS Attacker IP block action: {action}. Agent: {agent_name}. Alert ID: {alert_id}",
        "to_ids": True if action == "add" else False
    }

    logging.info(f"Sharing Threat Intel attribute with MISP (Action: {action})...")
    ok, code, res = send_http_request(url, payload, headers, timeout=timeout)
    if ok:
        logging.info(f"MISP Response [SUCCESS]: Code {code}")
    else:
        logging.error(f"MISP Response [FAILED]: Code {code}")

def main():
    if len(sys.argv) < 3:
        # Print basic usage error
        print("ERROR: Insufficient arguments. Usage:")
        print("1. Standard: soar_integrate.py <ACTION> <RAW_JSON_ALERT>")
        print("2. Legacy Fallback: soar_integrate.py <ACTION> <IP> <ALERT_ID> <RULE_ID> <DESCRIPTION>")
        sys.exit(1)

    action = sys.argv[1].lower()  # "add" or "delete"
    arg2 = sys.argv[2]

    # Initialize empty variables
    ip = "unknown"
    alert_id = "unknown"
    rule_id = "unknown"
    description = "DDoS Attack"
    agent_name = "unknown"
    rule_level = "unknown"

    # Attempt to parse raw JSON alert payload
    is_json = False
    if arg2.strip().startswith('{') and arg2.strip().endswith('}'):
        try:
            alert_data = json.loads(arg2)
            is_json = True
            
            # Extract fields safely from Wazuh alert structure
            alert_obj = alert_data.get("parameters", {}).get("alert", {})
            if not alert_obj:
                alert_obj = alert_data  # Direct mapping fallback

            alert_id = alert_obj.get("id", "unknown")
            rule_obj = alert_obj.get("rule", {})
            rule_id = rule_obj.get("id", "unknown")
            rule_level = str(rule_obj.get("level", "unknown"))
            description = rule_obj.get("description", "DDoS Attack")
            
            data_obj = alert_obj.get("data", {})
            ip = data_obj.get("srcip") or alert_obj.get("srcip") or data_obj.get("src_ip") or "unknown"
            
            agent_obj = alert_obj.get("agent", {})
            agent_name = agent_obj.get("name", "unknown")
        except Exception as e:
            # Print printout but try legacy fallback if other arguments exist
            print(f"Warning: Failed parsing alert JSON string: {e}")

    if not is_json:
        # Fallback to legacy arguments if JSON parsing is skipped or fails
        if len(sys.argv) < 6:
            print("ERROR: Parsing raw alert JSON failed, and legacy arguments are insufficient.")
            sys.exit(1)
        ip = sys.argv[2]
        alert_id = sys.argv[3]
        rule_id = sys.argv[4]
        description = sys.argv[5]

    # Load configuration and setup rotating file logs
    config = load_config()
    setup_logging(config)

    logging.info(f"===========================================================")
    logging.info(f"Processing SOAR Integration Trigger | Action: {action.upper()} | Attacker: {ip}")
    logging.info(f"Rule ID: {rule_id} (Level: {rule_level}) | Alert ID: {alert_id} | Agent: {agent_name}")
    logging.info(f"===========================================================")

    # Use ThreadPoolExecutor to call Shuffle, TheHive, and MISP in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        futures = {
            executor.submit(trigger_shuffle, config, action, ip, alert_id, rule_id, description, agent_name, rule_level): "Shuffle",
            executor.submit(trigger_thehive, config, action, ip, alert_id, rule_id, description, agent_name, rule_level): "TheHive",
            executor.submit(trigger_misp, config, action, ip, alert_id, rule_id, description, agent_name, rule_level): "MISP"
        }
        
        for future in concurrent.futures.as_completed(futures):
            service = futures[future]
            try:
                # Retrieve exceptions if any occurred inside the thread
                future.result()
            except Exception as e:
                logging.error(f"Execution error on parallel job for {service}: {e}")

    logging.info(f"SOAR Integration Trigger completed for Action: {action.upper()}")

if __name__ == "__main__":
    main()
