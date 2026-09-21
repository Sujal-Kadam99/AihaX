import json
import subprocess

cookie = "PHPSESSID=03k72kajhe34k2lee8pqla10m4; security=low"
cmd = [
    r"bin\tools\katana.exe",
    "-u", "http://localhost:8080/vulnerabilities/sqli/",
    "-u", "http://localhost:8080/vulnerabilities/xss_r/",
    "-H", f"Cookie: {cookie}",
    "-fx",
    "-j",
    "-d", "2",
    "-silent",
    "-duc"
]

proc = subprocess.run(cmd, capture_output=True, text=True)
print("Katana Output lines:", len(proc.stdout.splitlines()))
for line in proc.stdout.splitlines():
    try:
        d = json.loads(line)
        print("\nRecord:", json.dumps(d, indent=2))
    except Exception as e:
        print("Line:", line)
