# 🛡️ Automated DDoS Detection and Response
### Wazuh SIEM + SOAR Integration (Shuffle Cloud + Jira + Telegram)
**SOC & MIKS Course — Institut Teknologi Sepuluh Nopember (ITS)**

---

## 👥 Akses Platform untuk Tim

> Bagian ini berisi informasi cara bergabung ke semua platform yang digunakan dalam proyek ini.

### 🔀 Shuffle Cloud (SOAR Orchestrator)
| Info | Detail |
|---|---|
| **URL** | https://shuffler.io |
| **Workflow** | DDoS Auto Response |
| **Webhook URL** | `https://shuffler.io/api/v1/hooks/webhook_4b677c5b-3509-4060-86f7-87d122b9d57b` |

**Cara join sebagai anggota tim:**
1. Daftar akun di https://shuffler.io (gratis)
2. Minta owner workflow untuk invite via **Organizations** → **Members** → **Invite**
3. Setelah di-invite, workflow "DDoS Auto Response" akan muncul di dashboard

**Atau akses workflow langsung (read-only):**
- Login → klik **Workflows** → cari "DDoS Auto Response"

---

### 📋 Jira (Case / Ticket Management)
| Info | Detail |
|---|---|
| **URL** | `https://[DOMAIN].atlassian.net` |
| **Project Key** | `STD` |
| **Issue Type** | Bug (DDoS Incident) |
| **Labels** | `DDoS`, `AutoBlocked`, `Wazuh` |

**Cara join project Jira:**
1. Daftar akun Jira Cloud gratis di https://atlassian.com
2. Minta Project Admin untuk invite email kamu via:
   **Project Settings** → **People** → **Add people** → masukkan email
3. Role yang diberikan: **Developer** atau **Viewer**

**Lihat tiket yang sudah dibuat:**
- Login Jira → pilih project **STD** → klik **Board** atau **Backlog**
- Filter by label: `DDoS` untuk lihat semua insiden

---

### 📱 Telegram (Real-time Notifications)
| Info | Detail |
|---|---|
| **Bot Name** | *(nama bot kalian)* |
| **Bot Token** | `8773538330:AAGwpXP...` *(jangan share publik!)* |
| **Tipe notif** | Alert saat IP di-block & di-unblock |

**Cara terima notifikasi:**
1. Cari bot di Telegram: `@[nama_bot_kalian]`
2. Klik **START**
3. Minta owner untuk tambahkan chat_id kamu ke grup notifikasi, **ATAU**
4. Buat **Telegram Group** → tambahkan bot ke group → gunakan group chat_id

**Cara dapat chat_id grup:**
```bash
# Setelah bot ditambah ke grup, jalankan:
curl "https://api.telegram.org/bot<TOKEN>/getUpdates"
# Cari "chat":{"id": -XXXXXXXXX} — angka negatif = grup
```

Lalu update `soar_integrate.py`:
```python
TELEGRAM_CHAT_ID = "-XXXXXXXXX"  # chat_id grup (angka negatif)
```

---

## 🏛️ Arsitektur Sistem

```
[Attacker VM]
     │ SYN Flood (hping3)
     ▼
[Target VM - Agent-1]
     │ UFW BLOCK log → syslog
     ▼
[Wazuh Agent Service]
     │ Event forwarding
     ▼
[Wazuh Manager VM] ──── Rule 100200: UFW BLOCK detected
     │                   Rule 100201: 3x dalam 60 detik → TRIGGER
     ▼
[Active Response: ddos-block.sh]
     │
     ├──→ [iptables DROP] ← Local mitigation langsung
     │
     └──→ [soar_integrate.py]
               │
               ├──→ [Shuffle Cloud :5001] → SOAR Webhook
               ├──→ [Jira REST API]       → Create/Close Ticket
               └──→ [Telegram Bot API]    → Real-time Alert
```

---

## 📁 Struktur Repository

```
├── wazuh/
│   ├── rules/
│   │   └── local_rules.xml          # Custom DDoS detection rules
│   └── decoders/
│       └── local_decoder.xml        # Custom UFW log decoders
├── active-response/
│   ├── ddos-block.sh                # Active response handler
│   └── soar_integrate.py            # SOAR integration gateway
├── soar-mock/
│   └── soar_mock.py                 # Mock listener (testing)
└── README.md
```

---

## ⚙️ Konfigurasi (`soar_integrate.py`)

Sebelum deploy, update bagian config berikut:

```python
# ─── SHUFFLE ───────────────────────────────────
SHUFFLE_WEBHOOK_URL = "https://shuffler.io/api/v1/hooks/webhook_4b677c5b-3509-4060-86f7-87d122b9d57b"

# ─── JIRA ──────────────────────────────────────
JIRA_DOMAIN      = "https://[DOMAIN].atlassian.net"
JIRA_EMAIL       = "your@email.com"
JIRA_API_TOKEN   = "YOUR_JIRA_API_TOKEN"   # dari: id.atlassian.com/manage-profile/security/api-tokens
JIRA_PROJECT_KEY = "STD"

# ─── TELEGRAM ──────────────────────────────────
TELEGRAM_BOT_TOKEN = "8773538330:AAGwpXPVW9cJM4s61pIaC15aP4yxCrW2mgs"
TELEGRAM_CHAT_ID   = "6515107315"   # ganti ke group chat_id jika pakai grup
```

---

## 🛠️ Wazuh Rules & Decoder

### `wazuh/decoders/local_decoder.xml`
```xml
<decoder name="ufw-ddos">
  <parent>kernel</parent>
  <prematch>UFW BLOCK|UFW AUDIT</prematch>
  <regex>SRC=(\S+) DST=(\S+)</regex>
  <order>srcip, dstip</order>
</decoder>
```

### `wazuh/rules/local_rules.xml`
```xml
<group name="ddos,attack,">
  <rule id="100200" level="12">
    <decoded_as>kernel</decoded_as>
    <match>[UFW BLOCK]</match>
    <description>Possible DDoS: Inbound traffic blocked</description>
  </rule>

  <!-- Trigger setelah 3x event dalam 60 detik dari IP yang sama -->
  <rule id="100201" level="14" frequency="3" timeframe="60">
    <if_matched_sid>100200</if_matched_sid>
    <same_source_ip />
    <description>DDoS Attack: High frequency - SOAR Triggered</description>
  </rule>
</group>
```

---

## 🔀 Shuffle Cloud Workflow

### Flow Diagram
```
[Webhook_1] ──── action == ADD ────→ [Telegram - DDoS Alert] ──→ [Jira - Create Ticket]
            └─── action == DELETE ──→ [Telegram - Unblock]
```

### Konfigurasi Node Telegram - DDoS Alert
```
Method : POST
URL    : https://api.telegram.org/bot<TOKEN>/sendMessage
Headers: Content-Type: application/json
Body   :
{
  "chat_id": "6515107315",
  "parse_mode": "Markdown",
  "text": "🚨 DDoS ALERT\nAction: $exec.action\nIP: $exec.attacker_ip\nRule: $exec.rule_id Level $exec.rule_level\nAgent: $exec.agent\nTime: $exec.timestamp"
}
```

### Konfigurasi Node Jira - Create Ticket
```
Method : POST
URL    : https://[DOMAIN].atlassian.net/rest/api/2/issue
Headers:
  Authorization: Basic <BASE64(email:api_token)>
  Content-Type: application/json
Body   :
{
  "fields": {
    "project":     { "key": "STD" },
    "summary":     "[DDoS] Attack from $exec.attacker_ip - Alert $exec.alert_id",
    "description": "Rule: $exec.rule_id (Level $exec.rule_level)\nAgent: $exec.agent\nTime: $exec.timestamp",
    "issuetype":   { "name": "Bug" },
    "priority":    { "name": "High" },
    "labels":      ["DDoS", "AutoBlocked"]
  }
}
```

### Cara generate Authorization header:
```bash
echo -n "your@email.com:YOUR_API_TOKEN" | base64
```

### Kondisi Branch (Conditions):
| Edge | Parameter 1 | Condition | Parameter 2 |
|---|---|---|---|
| Webhook → Telegram Alert | `$exec.action` | equals | `ADD` |
| Webhook → Jira Create | `$exec.action` | equals | `ADD` |
| Webhook → Telegram Unblock | `$exec.action` | equals | `DELETE` |

---

## 🧪 Cara Testing

### 1. Test Manual Webhook Shuffle
```bash
# Test ADD (simulasi IP di-block)
curl -X POST "https://shuffler.io/api/v1/hooks/webhook_4b677c5b-3509-4060-86f7-87d122b9d57b" \
  -H "Content-Type: application/json" \
  -d '{"action":"ADD","attacker_ip":"10.0.0.5","alert_id":"test-001","rule_id":"100201","rule_level":"14","agent":"wazuh-agent-1","timestamp":"2026-06-02T10:00:00"}'

# Test DELETE (simulasi IP di-unblock)
curl -X POST "https://shuffler.io/api/v1/hooks/webhook_4b677c5b-3509-4060-86f7-87d122b9d57b" \
  -H "Content-Type: application/json" \
  -d '{"action":"DELETE","attacker_ip":"10.0.0.5","alert_id":"test-001","rule_id":"100201","rule_level":"14","agent":"wazuh-agent-1","timestamp":"2026-06-02T10:00:00"}'
```

### 2. Test soar_integrate.py Langsung
```bash
sudo python3 /var/ossec/active-response/bin/soar_integrate.py add '{
  "parameters": {
    "alert": {
      "id": "9999.1234",
      "timestamp": "2026-06-02T10:00:00",
      "agent": {"name": "wazuh-agent-1"},
      "rule": {"id": "100201", "level": "14", "description": "DDoS Attack: High frequency"},
      "data": {"srcip": "10.0.0.5"}
    }
  }
}'
```

### 3. Cek Log
```bash
sudo tail -f /var/log/soar-integrations.log
```

### 4. Simulasi Serangan Nyata
```bash
# Dari Attacker VM (Agent-2)
sudo hping3 -S -p 80 -c 100 --fast 10.0.0.4

# Verifikasi iptables di Target VM (Agent-1)
sudo iptables -L INPUT -n -v

# Verifikasi alert Wazuh
sudo grep -i '100201' /var/ossec/logs/alerts/alerts.json
```

---

## ✅ Hasil Simulasi

| Komponen | Status | Detail |
|---|---|---|
| Wazuh Rule 100200 | ✅ | Fired 27x saat flood |
| Wazuh Rule 100201 | ✅ | Triggered setelah threshold |
| iptables DROP | ✅ | 124K packets dropped dari 10.0.0.5 |
| soar_integrate.py | ✅ | Eksekusi < 1 detik |
| Telegram Alert | ✅ | Notif real-time diterima |
| Jira Ticket | ✅ | Issue dibuat otomatis (STD-1, STD-2, ...) |
| Shuffle Webhook | ✅ | HTTP 200 |

### Sample Log Output
```
[2026-06-02 15:49:54] [INFO] Processing | Action: ADD | Attacker: 10.0.0.5
[2026-06-02 15:49:55] [INFO] Telegram [SUCCESS]: Telegram OK [200]
[2026-06-02 15:49:55] [INFO] Shuffle  [SUCCESS]: Shuffle OK [200]
[2026-06-02 15:49:55] [INFO] Jira     [SUCCESS]: Jira ticket CREATED: STD-2
[2026-06-02 15:49:55] [INFO] SOAR Integration completed for Action: ADD
```

---

## 🚀 Setup dari Awal (untuk anggota tim baru)

### Prerequisites
- Akun Shuffle Cloud: https://shuffler.io
- Akun Jira Cloud: https://atlassian.com
- Telegram bot sudah di-START

### 1. Clone repo
```bash
git clone https://github.com/[USERNAME]/[REPO_NAME].git
cd [REPO_NAME]
```

### 2. Deploy ke Wazuh Agent
```bash
# Copy active response scripts
sudo cp active-response/ddos-block.sh /var/ossec/active-response/bin/
sudo cp active-response/soar_integrate.py /var/ossec/active-response/bin/

# Set permission
sudo chmod +x /var/ossec/active-response/bin/ddos-block.sh
sudo chmod +x /var/ossec/active-response/bin/soar_integrate.py
sudo chown root:wazuh /var/ossec/active-response/bin/soar_integrate.py

# Copy rules & decoders ke Wazuh Manager
sudo cp wazuh/rules/local_rules.xml /var/ossec/etc/rules/
sudo cp wazuh/decoders/local_decoder.xml /var/ossec/etc/decoders/

# Restart Wazuh Manager
sudo systemctl restart wazuh-manager
```

### 3. Update config di soar_integrate.py
```bash
sudo nano /var/ossec/active-response/bin/soar_integrate.py
# Update: SHUFFLE_WEBHOOK_URL, JIRA_*, TELEGRAM_*
```

### 4. Install dependencies Python
```bash
sudo pip3 install requests --break-system-packages
```

### 5. Test
```bash
sudo tail -f /var/log/soar-integrations.log
```

---

## 🔐 Catatan Keamanan

> **PENTING:** Jangan pernah commit credential ke GitHub!

Tambahkan ke `.gitignore`:
```
*.env
secrets.py
config_private.py
```

Gunakan environment variable untuk production:
```bash
export TELEGRAM_BOT_TOKEN="your_token"
export JIRA_API_TOKEN="your_token"
```

---

## 👨‍💻 Tim

| Nama | Role |
|---|---|
| *(isi nama tim)* | Wazuh Engineer |
| *(isi nama tim)* | SOAR Developer |
| *(isi nama tim)* | Security Analyst |

**Institut Teknologi Sepuluh Nopember (ITS)**
SOC & MIKS Course — 2026
