import asyncio
from playwright.async_api import async_playwright

async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        print("Navigating to frontend...")
        try:
            await page.goto('http://127.0.0.1:3000')
            await page.wait_for_timeout(3000)
            await page.screenshot(path='frontend_initial.png')
            print("Screenshot saved to frontend_initial.png")
            print("Page title:", await page.title())
            
            # Print some HTML to see what's there
            content = await page.content()
            print("HTML Snippet:", content[:1000])
        except Exception as e:
            print("Error:", e)
        finally:
            await browser.close()

if __name__ == '__main__':
    asyncio.run(main())
