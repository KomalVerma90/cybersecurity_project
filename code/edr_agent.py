import os
import time
import hashlib
import socket
import json
import argparse
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# MITRE ATT&CK Mapping
MITRE_MAP = {
    'file_change': {'id': 'TA0005', 'name': 'Defense Evasion', 'technique': 'T1070 - Indicator Removal'}
}

class FIMHandler(FileSystemEventHandler):
    def __init__(self, paths, baseline_hashes, server_host, server_port):
        self.paths = paths
        self.baseline_hashes = baseline_hashes
        self.server_host = server_host
        self.server_port = server_port

    def on_modified(self, event):
        if not event.is_directory:
            self.check_integrity(event.src_path)

    def check_integrity(self, path):
        if path in self.baseline_hashes:
            try:
                with open(path, 'rb') as f:
                    current_hash = hashlib.sha256(f.read()).hexdigest()
                if current_hash != self.baseline_hashes[path]:
                    alert = {
                        'type': 'file_change',
                        'path': path,
                        'mitre': MITRE_MAP['file_change'],
                        'message': 'File integrity violation detected!'
                    }
                    self.send_alert(alert)
                    # Update baseline so it doesn't alert repeatedly
                    self.baseline_hashes[path] = current_hash
            except Exception as e:
                print(f"Error checking {path}: {e}")

    def send_alert(self, alert):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((self.server_host, self.server_port))
                s.sendall(json.dumps(alert).encode('utf-8'))
                print(f"[+] ALERT SENT: {alert['message']} ({alert['path']})")
        except Exception as e:
            print(f"[-] Could not send alert: {e}")

def compute_baseline(paths):
    baselines = {}
    for path in paths:
        if os.path.exists(path):
            try:
                with open(path, 'rb') as f:
                    baselines[path] = hashlib.sha256(f.read()).hexdigest()
                print(f"Baseline hash computed: {baselines[path][:16]}... for {path}")
            except Exception as e:
                print(f"Error hashing {path}: {e}")
    return baselines

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--platform', choices=['windows', 'linux'], required=True)
    parser.add_argument('--server_host', default='127.0.0.1')
    parser.add_argument('--server_port', type=int, default=5000)
    args = parser.parse_args()

    # Create safe test file
    test_dir = r'C:\temp'
    test_file = os.path.join(test_dir, 'test.txt')
    os.makedirs(test_dir, exist_ok=True)
    if not os.path.exists(test_file):
        with open(test_file, 'w') as f:
            f.write('Safe initial content - monitored by EDR agent.\n')

    paths = [test_file]
    print(f"[+] Monitoring: {test_file}")

    baselines = compute_baseline(paths)

    observer = Observer()
    handler = FIMHandler(paths, baselines, args.server_host, args.server_port)
    observer.schedule(handler, os.path.dirname(test_file), recursive=False)
    observer.start()

    print("[+] EDR AGENT STARTED - Waiting for changes...")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[-] Stopping agent...")
        observer.stop()
    observer.join()

if __name__ == '__main__':
    main()
