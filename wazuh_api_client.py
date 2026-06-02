#!/usr/bin/env python3
import urllib.request
import urllib.error
import ssl
import json
import sys
import base64

# Kredensial dari Catatan.docx
WAZUH_IP = "4.186.24.41"
PORT = 55000
USERNAME = "wazuh-wui"
PASSWORD = "5*0duV7vAW?D*GCp2uUId5AMMXx4l?WI"

def get_ssl_context():
    # Mengabaikan self-signed certificate SSL
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

def get_jwt_token(ctx):
    url = f"https://{WAZUH_IP}:{PORT}/security/user/authenticate"
    auth_str = f"{USERNAME}:{PASSWORD}"
    auth_b64 = base64.b64encode(auth_str.encode('utf-8')).decode('utf-8')
    
    req = urllib.request.Request(
        url,
        headers={"Authorization": f"Basic {auth_b64}"},
        method='GET'
    )
    
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=10) as response:
            res = json.loads(response.read().decode('utf-8'))
            return res.get("data", {}).get("token")
    except urllib.error.URLError as e:
        print(f"Error Koneksi: {e.reason}")
        print("Pastikan VM Wazuh Manager (4.186.24.41) sudah dinyalakan di Azure.")
        sys.exit(1)
    except Exception as e:
        print(f"Gagal mengambil token: {e}")
        sys.exit(1)

def query_endpoint(ctx, token, endpoint):
    url = f"https://{WAZUH_IP}:{PORT}{endpoint}"
    req = urllib.request.Request(
        url,
        headers={"Authorization": f"Bearer {token}"},
        method='GET'
    )
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=10) as response:
            return json.loads(response.read().decode('utf-8'))
    except Exception as e:
        return {"error": str(e)}

def main():
    if len(sys.argv) < 2:
        print("Penggunaan:")
        print("  python wazuh_api_client.py <endpoint>")
        print("Contoh:")
        print("  python wazuh_api_client.py /manager/info")
        print("  python wazuh_api_client.py /agents")
        sys.exit(0)
        
    endpoint = sys.argv[1]
    if not endpoint.startswith('/'):
        endpoint = '/' + endpoint
        
    ctx = get_ssl_context()
    
    print("Mengambil JWT token dari Wazuh...")
    token = get_jwt_token(ctx)
    print("Autentikasi Berhasil!")
    print(f"Melakukan request ke: {endpoint}...")
    
    res = query_endpoint(ctx, token, endpoint)
    print("\nHasil Response:")
    print(json.dumps(res, indent=2))

if __name__ == "__main__":
    main()
