#!/usr/bin/env python3
import http.server
import socketserver
import threading
import json
import datetime
import os

LOG_FILE = "/var/log/soar-integrations.log"

def log(message):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_line = f"[{timestamp}] [MOCK-SERVICE] {message}\n"
    print(log_line.strip())
    try:
        with open(LOG_FILE, "a") as f:
            f.write(log_line)
    except Exception as e:
        print(f"Failed to write to log file: {e}")

class MockHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Override to suppress standard HTTP logging to stdout/stderr
        pass

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')
        port = self.server.server_address[1]

        # Parse request body
        try:
            payload = json.loads(post_data)
        except Exception:
            payload = post_data

        # Determine which service is hit based on port
        if port == 5001:
            service = "Shuffle"
            response = {"status": "success", "message": "Workflow triggered successfully in Shuffle"}
        elif port == 9000:
            service = "TheHive"
            response = {"status": "success", "id": "case-9999", "message": "TheHive Case created"}
        elif port == 6666:
            service = "MISP"
            response = {"status": "success", "message": "Attribute added to MISP event"}
        else:
            service = "Unknown"
            response = {"status": "error", "message": "Unknown service"}

        log(f"--- Received Request on Port {port} ({service}) ---")
        log(f"Headers: {dict(self.headers)}")
        log(f"Payload: {json.dumps(payload, indent=2)}")

        # Send response
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(response).encode('utf-8'))

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True

def start_server(port):
    handler = MockHandler
    server = ThreadedTCPServer(('0.0.0.0', port), handler)
    log(f"Started Mock Server for {port}...")
    server.serve_forever()

if __name__ == '__main__':
    # Initialize the log file with correct permissions if possible
    try:
        if not os.path.exists(LOG_FILE):
            with open(LOG_FILE, 'w') as f:
                f.write("=== SOAR Integration Mock Services Log ===\n")
            os.chmod(LOG_FILE, 0o666)
    except Exception as e:
        print(f"Log init warning: {e}")

    # Launch servers on ports 5001, 9000, and 6666 in separate threads
    threads = []
    for port in [5001, 9000, 6666]:
        t = threading.Thread(target=start_server, args=(port,), daemon=True)
        t.start()
        threads.append(t)

    log("SOAR Mock Services listening on ports: 5001 (Shuffle), 9000 (TheHive), 6666 (MISP). Press Ctrl+C to stop.")
    
    # Keep main thread alive
    try:
        import time
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log("Stopping SOAR Mock Services...")
