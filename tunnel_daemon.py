import subprocess
import time
import re
import sys
import os

url_file = os.path.join(os.path.dirname(__file__), "tunnel_url.txt")

def start_tunnel():
    cmd = [
        "ssh",
        "-T",
        "-o", "StrictHostKeyChecking=no",
        "-o", "ServerAliveInterval=15",
        "-o", "ServerAliveCountMax=3",
        "-R", "80:127.0.0.1:8050",
        "nokey@localhost.run"
    ]
    print("Starting SSH tunnel to localhost.run...")
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    
    url = None
    for line in iter(proc.stdout.readline, ''):
        print(line, end='', flush=True)
        m = re.search(r'(https://[a-zA-Z0-9\.\-]+\.lhr\.life)', line)
        if m:
            url = m.group(1)
            print(f"\n==========================================")
            print(f"PUBLIC PROTOTYPE URL: {url}")
            print(f"==========================================\n", flush=True)
            with open(url_file, "w") as f:
                f.write(url.strip())
                
    proc.wait()

while True:
    try:
        start_tunnel()
    except Exception as e:
        print(f"Tunnel error: {e}")
    time.sleep(3)
