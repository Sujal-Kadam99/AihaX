import time
import requests
from backend.core.auth import get_or_create_api_token
from backend.models.database import get_db, Finding, Scan
import json

TARGET_URL = "http://localhost:3001"
API_URL = "http://localhost:8000/api"

# 1. Wait for Juice Shop
print(f"Waiting for {TARGET_URL} to be healthy...")
while True:
    try:
        r = requests.get(TARGET_URL)
        if r.status_code == 200:
            print("Juice Shop is UP!")
            break
    except:
        pass
    time.sleep(1)

# 2. Get API Token
token = get_or_create_api_token()
headers = {"X-AihaX-Token": token}

# 3. Start Scan
print("Starting AihaX scan...")
payload = {
  "target_url": TARGET_URL,
  "scan_depth": "deep",
  "scan_mode": "standard",
  "threads": 5,
  "authorization_confirmed": True,
  "scope_notes": "Authorized local test against intentionally vulnerable OWASP Juice Shop container",
  "stealth_mode": False,
  "admin_mode": False
}

r = requests.post(f"{API_URL}/scan/start", json=payload, headers=headers)
if r.status_code != 200:
    print("Failed to start scan:", r.text)
    exit(1)

scan_id = r.json()["scan_id"]
print(f"Scan started with ID: {scan_id}")

# 4. Poll Status
while True:
    r = requests.get(f"{API_URL}/scan/{scan_id}", headers=headers)
    data = r.json()
    status = data.get("status")
    print(f"Status: {status}...")
    if status in ("completed", "failed", "cancelled"):
        break
    time.sleep(5)

# 5. Fetch Findings
print("Scan finished! Fetching findings...")
db = next(get_db())
findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()

results = []
for f in findings:
    results.append({
        "id": f.id,
        "title": f.title,
        "vuln_type": f.vuln_type,
        "verdict": f.verdict,
        "verification_status": getattr(f, "verification_status", None),
        "disposition": getattr(f, "finding_disposition", None),
        "confidence": f.confidence,
        "severity": f.severity,
        "url": getattr(f, "url", ""),
    })

with open("scan_results.json", "w") as f:
    json.dump(results, f, indent=2)

print(f"Saved {len(results)} findings to scan_results.json")
