import subprocess, json, requests

s = requests.Session()
r1 = s.get("http://localhost:8080/login.php")
token = ""
for line in r1.text.splitlines():
    if "user_token" in line and "value=" in line:
        token = line.split("value='")[1].split("'")[0] if "value='" in line else line.split('value="')[1].split('"')[0]

resp = s.post("http://localhost:8080/login.php", data={"username": "admin", "password": "password", "Login": "Login", "user_token": token})
s.cookies.set("security", "low")

cookie_str = f"PHPSESSID={s.cookies.get('PHPSESSID')}; security=low"
print("Cookie string:", cookie_str)

cmd = [
    "katana",
    "-u", "http://localhost:8080/vulnerabilities/xss_r/",
    "-duc",
    "-silent",
    "-d", "1",
    "-timeout", "5",
    "-j",
    "-fx",
    "-H", f"Cookie: {cookie_str}"
]

res = subprocess.run(cmd, capture_output=True, text=True)
print("Exit code:", res.returncode)
print("Stdout lines:", len(res.stdout.splitlines()))
for line in res.stdout.splitlines():
    print("LINE:", line)
