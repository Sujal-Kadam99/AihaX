import requests

SCAN_ID = "e57b0a10-0dc9-4f26-8a5d-773fbab6a7db"
token = requests.get("http://localhost:8000/api/auth/token").json()["token"]
headers = {"X-AihaX-Token": token}

print(f"Downloading updated report for scan {SCAN_ID}...")
report_res = requests.get(
    f"http://localhost:8000/api/reports/scan/{SCAN_ID}",
    headers=headers,
)
print(f"HTTP status: {report_res.status_code}")

if report_res.status_code == 200:
    content = report_res.content
    outfile = "report_output_v2.pdf" if content[:4] == b"%PDF" else "report_output_v2.html"
    with open(outfile, "wb") as f:
        f.write(content)
    print(f"SUCCESS: Saved as {outfile} ({len(content):,} bytes)")
    import subprocess
    subprocess.Popen(["start", outfile], shell=True)
    print("Opened for review!")
else:
    print(f"ERROR {report_res.status_code}: {report_res.text[:300]}")
