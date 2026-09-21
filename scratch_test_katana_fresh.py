import asyncio
import json
import subprocess
from playwright.async_api import async_playwright

async def run_test():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        await page.goto("http://localhost:8080/login.php")
        await page.fill("input[name='username']", "admin")
        await page.fill("input[name='password']", "password")
        await page.click("input[name='Login']")
        await page.wait_for_timeout(500)
        
        cookies = await page.context.cookies()
        cookie_header = "; ".join(f"{c['name']}={c['value']}" for c in cookies)
        print("Fresh Cookie:", cookie_header)
        await browser.close()
        
    cmd = [
        r"bin\tools\katana.exe",
        "-u", "http://localhost:8080/vulnerabilities/sqli/",
        "-u", "http://localhost:8080/vulnerabilities/xss_r/",
        "-H", f"Cookie: {cookie_header}",
        "-fx",
        "-jc",
        "-j",
        "-d", "2",
        "-silent",
        "-duc"
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    print("Katana Output lines:", len(proc.stdout.splitlines()))
    for i, line in enumerate(proc.stdout.splitlines()):
        try:
            d = json.loads(line)
            print(f"\n--- Line #{i+1} ---")
            print(json.dumps(d, indent=2))
        except Exception:
            print(f"Line #{i+1} (raw):", line)

if __name__ == "__main__":
    asyncio.run(run_test())
