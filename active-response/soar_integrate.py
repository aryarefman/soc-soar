#!/usr/bin/env python3
"""
soar_integrate.py - DDoS SOAR Integration Gateway
ITS MIKS - Updated: Shuffle Cloud + Jira + Telegram
"""

import sys
import json
import logging
import requests
import base64
import os
from logging.handlers import RotatingFileHandler
from concurrent.futures import ThreadPoolExecutor, as_completed

# ─────────────────────────────────────────────
# CONFIG - Sesuaikan dengan nilai kamu
# ─────────────────────────────────────────────
# Default placeholders (safe for GitHub)
SHUFFLE_WEBHOOK_URL = "https://shuffler.io/api/v1/hooks/webhook_placeholder"
JIRA_DOMAIN       = "https://your-domain.atlassian.net"
JIRA_EMAIL        = "your-email@example.com"
JIRA_API_TOKEN    = "JIRA_API_TOKEN_PLACEHOLDER"
JIRA_PROJECT_KEY  = "STD"
TELEGRAM_BOT_TOKEN = "TELEGRAM_BOT_TOKEN_PLACEHOLDER"
TELEGRAM_CHAT_ID   = "TELEGRAM_CHAT_ID_PLACEHOLDER"

# Dynamic Secrets Loading
SECRETS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "secrets.json")
if os.path.exists(SECRETS_FILE):
    try:
        with open(SECRETS_FILE, "r") as f:
            secrets = json.load(f)
            SHUFFLE_WEBHOOK_URL = secrets.get("SHUFFLE_WEBHOOK_URL", SHUFFLE_WEBHOOK_URL)
            JIRA_DOMAIN       = secrets.get("JIRA_DOMAIN", JIRA_DOMAIN)
            JIRA_EMAIL        = secrets.get("JIRA_EMAIL", JIRA_EMAIL)
            JIRA_API_TOKEN    = secrets.get("JIRA_API_TOKEN", JIRA_API_TOKEN)
            JIRA_PROJECT_KEY  = secrets.get("JIRA_PROJECT_KEY", JIRA_PROJECT_KEY)
            TELEGRAM_BOT_TOKEN = secrets.get("TELEGRAM_BOT_TOKEN", TELEGRAM_BOT_TOKEN)
            TELEGRAM_CHAT_ID   = secrets.get("TELEGRAM_CHAT_ID", TELEGRAM_CHAT_ID)
    except Exception as e:
        sys.stderr.write(f"Warning: Failed to load secrets from {SECRETS_FILE}: {e}\n")

LOG_FILE = "/var/log/soar-integrations.log"
TIMEOUT  = 10  # seconds
# ─────────────────────────────────────────────

# Setup rotating logger
logger = logging.getLogger("SOAR-GATEWAY")
logger.setLevel(logging.INFO)
handler = RotatingFileHandler(LOG_FILE, maxBytes=10*1024*1024, backupCount=5)
handler.setFormatter(logging.Formatter('[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s'))
logger.addHandler(handler)


def parse_alert(raw_input: str, action_arg: str) -> dict:
    """Parse Wazuh JSON alert payload."""
    try:
        data = json.loads(raw_input)
        alert = data.get("parameters", {}).get("alert", {})
        return {
            "action":      action_arg.upper(),
            "src_ip":      (alert.get("data", {}).get("srcip")
                            or alert.get("srcip")
                            or alert.get("data", {}).get("src_ip", "UNKNOWN")),
            "alert_id":    alert.get("id", "unknown"),
            "rule_id":     alert.get("rule", {}).get("id", "unknown"),
            "rule_level":  alert.get("rule", {}).get("level", "unknown"),
            "description": alert.get("rule", {}).get("description", "DDoS Attack Detected"),
            "agent_name":  alert.get("agent", {}).get("name", "unknown"),
            "timestamp":   alert.get("timestamp", "unknown"),
        }
    except (json.JSONDecodeError, KeyError) as e:
        logger.error(f"Failed to parse alert JSON: {e}")
        return {
            "action": action_arg.upper(), "src_ip": "UNKNOWN",
            "alert_id": "unknown", "rule_id": "unknown",
            "rule_level": "unknown", "description": "DDoS Attack Detected",
            "agent_name": "unknown", "timestamp": "unknown",
        }


def trigger_shuffle(ctx: dict) -> str:
    """POST alert context ke Shuffle Cloud Webhook."""
    payload = {
        "source":      "wazuh-active-response",
        "action":      ctx["action"],
        "attacker_ip": ctx["src_ip"],
        "alert_id":    ctx["alert_id"],
        "rule_id":     ctx["rule_id"],
        "rule_level":  ctx["rule_level"],
        "description": ctx["description"],
        "agent":       ctx["agent_name"],
        "timestamp":   ctx["timestamp"],
    }
    resp = requests.post(SHUFFLE_WEBHOOK_URL, json=payload, timeout=TIMEOUT)
    resp.raise_for_status()
    return f"Shuffle OK [{resp.status_code}]"


def create_jira_ticket(ctx: dict) -> str:
    """Buat atau update Jira issue berdasarkan action."""
    token_b64 = base64.b64encode(
        f"{JIRA_EMAIL}:{JIRA_API_TOKEN}".encode()
    ).decode()
    headers = {
        "Authorization": f"Basic {token_b64}",
        "Content-Type":  "application/json",
    }

    if ctx["action"] == "ADD":
        summary = f"[DDoS] Attack Detected from {ctx['src_ip']}"
        description = (
            f"*Alert ID:* {ctx['alert_id']}\n"
            f"*Rule:* {ctx['rule_id']} (Level {ctx['rule_level']})\n"
            f"*Description:* {ctx['description']}\n"
            f"*Agent:* {ctx['agent_name']}\n"
            f"*Timestamp:* {ctx['timestamp']}\n\n"
            f"*Mitigation:* iptables DROP rule applied automatically on {ctx['agent_name']}."
        )
        payload = {
            "fields": {
                "project":     {"key": JIRA_PROJECT_KEY},
                "summary":     summary,
                "description": description,
                "issuetype":   {"name": "Bug"},   # ganti ke "Incident" jika ada
                "priority":    {"name": "High"},
                "labels":      ["DDoS", "AutoBlocked", "Wazuh"],
            }
        }
        resp = requests.post(
            f"{JIRA_DOMAIN}/rest/api/2/issue",
            json=payload, headers=headers, timeout=TIMEOUT
        )
        resp.raise_for_status()
        issue_key = resp.json().get("key", "???")
        return f"Jira ticket CREATED: {issue_key}"

    else:  # DELETE / unblock
        # Search dulu issue yang open dengan IP tersebut
        jql = (f'project={JIRA_PROJECT_KEY} AND summary ~ "{ctx["src_ip"]}" '
               f'AND status != Done ORDER BY created DESC')
        search = requests.get(
            f"{JIRA_DOMAIN}/rest/api/2/search",
            params={"jql": jql, "maxResults": 1},
            headers=headers, timeout=TIMEOUT
        )
        search.raise_for_status()
        issues = search.json().get("issues", [])
        if not issues:
            return "Jira: no open issue found to update"

        issue_key = issues[0]["key"]
        # Add comment bahwa IP sudah di-unblock
        comment_payload = {
            "body": (f"✅ *IP {ctx['src_ip']} has been UNBLOCKED.*\n"
                     f"Firewall rule removed automatically at {ctx['timestamp']}.\n"
                     f"Alert ID: {ctx['alert_id']}")
        }
        requests.post(
            f"{JIRA_DOMAIN}/rest/api/2/issue/{issue_key}/comment",
            json=comment_payload, headers=headers, timeout=TIMEOUT
        ).raise_for_status()

        # Transition ke "Done" (cari transition ID dulu)
        trans_resp = requests.get(
            f"{JIRA_DOMAIN}/rest/api/2/issue/{issue_key}/transitions",
            headers=headers, timeout=TIMEOUT
        )
        trans_resp.raise_for_status()
        transitions = trans_resp.json().get("transitions", [])
        done_id = next(
            (t["id"] for t in transitions if "done" in t["name"].lower()), None
        )
        if done_id:
            requests.post(
                f"{JIRA_DOMAIN}/rest/api/2/issue/{issue_key}/transitions",
                json={"transition": {"id": done_id}},
                headers=headers, timeout=TIMEOUT
            ).raise_for_status()

        return f"Jira issue {issue_key} CLOSED (IP unblocked)"


def send_telegram(ctx: dict) -> str:
    """Kirim notifikasi Telegram."""
    if ctx["action"] == "ADD":
        emoji = "🚨"
        status_line = f"*IP `{ctx['src_ip']}` has been AUTO-BLOCKED*"
    else:
        emoji = "✅"
        status_line = f"*IP `{ctx['src_ip']}` has been UNBLOCKED*"

    message = (
        f"{emoji} *DDoS ALERT — {ctx['action']}*\n"
        f"{'─' * 30}\n"
        f"{status_line}\n\n"
        f"📋 *Alert ID:* `{ctx['alert_id']}`\n"
        f"⚠️ *Rule:* `{ctx['rule_id']}` *(Level {ctx['rule_level']})*\n"
        f"📝 *Desc:* {ctx['description']}\n"
        f"🖥️ *Agent:* `{ctx['agent_name']}`\n"
        f"🕐 *Time:* `{ctx['timestamp']}`\n"
    )
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    resp = requests.post(url, json={
        "chat_id":    TELEGRAM_CHAT_ID,
        "text":       message,
        "parse_mode": "Markdown",
    }, timeout=TIMEOUT)
    resp.raise_for_status()
    return f"Telegram OK [{resp.status_code}]"


def main():
    if len(sys.argv) < 3:
        logger.error("Usage: soar_integrate.py <add|delete> '<json_payload>'")
        sys.exit(1)

    action_arg = sys.argv[1]
    raw_input  = sys.argv[2]

    ctx = parse_alert(raw_input, action_arg)

    logger.info("=" * 55)
    logger.info(f"Processing | Action: {ctx['action']} | Attacker: {ctx['src_ip']}")
    logger.info(f"Rule: {ctx['rule_id']} (Level {ctx['rule_level']}) | Agent: {ctx['agent_name']}")
    logger.info("=" * 55)

    # Jalankan semua integrasi secara paralel
    tasks = {
        "Shuffle":  trigger_shuffle,
        "Jira":     create_jira_ticket,
        "Telegram": send_telegram,
    }

    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = {executor.submit(fn, ctx): name for name, fn in tasks.items()}
        for future in as_completed(futures):
            name = futures[future]
            try:
                result = future.result()
                logger.info(f"{name} [SUCCESS]: {result}")
            except Exception as e:
                logger.error(f"{name} [FAILED]: {e}")

    logger.info(f"SOAR Integration completed for Action: {ctx['action']}\n")


if __name__ == "__main__":
    main()
