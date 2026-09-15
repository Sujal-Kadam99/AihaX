import requests
token = requests.get("http://localhost:8000/api/auth/token").json()["token"]
payload = {
    "target_url": "https://pentest-ground.com:4280",
    "scan_mode": "standard",
    "scan_depth": "normal",
    "threads": 5,
    "waf_bypass": False,
    "stealth_mode": False,
    "two_fa_type": "none",
    "authorization_confirmed": True,
    "scope_notes": "I have explicit authorization to perform security testing on this target application."
}
headers = {"X-AihaX-Token": token, "Content-Type": "application/json"}
res = requests.post("http://localhost:8000/api/scan/start", json=payload, headers=headers)
print("STATUS:", res.status_code)
print("BODY:", res.json())
