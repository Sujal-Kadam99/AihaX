import asyncio
import json
import subprocess
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scratch.kill_scratch_ports import kill as kill_ports
from scratch.new_5_targets_app import app as vuln_app
from werkzeug.serving import make_server

def start_vuln_server(port=5005):
    kill_ports([port])
    server = make_server("127.0.0.1", port, vuln_app, threaded=True)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server

def run_katana_test():
    port = 5005
    server = start_vuln_server(port)
    target_url = f"http://127.0.0.1:{port}"
    katana_path = Path(__file__).resolve().parent.parent / "bin" / "tools" / "katana.exe"
    
    print(f"[*] Testing Katana binary at {katana_path} against {target_url}...")
    try:
        cmd = [
            str(katana_path),
            "-u", target_url,
            "-duc",
            "-silent",
            "-d", "2",
            "-timeout", "2",
            "-c", "5",
        ]
        result = subprocess.run(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15,
        )
        print(f"Return code: {result.returncode}")
        print(f"Stdout ({len(result.stdout.splitlines())} lines):")
        for line in result.stdout.splitlines():
            print(f"  > {line}")
        if result.stderr:
            print(f"Stderr:\n{result.stderr}")
    except Exception as e:
        print(f"Error executing katana: {e}")
    finally:
        server.shutdown()
        kill_ports([port])

if __name__ == "__main__":
    run_katana_test()
