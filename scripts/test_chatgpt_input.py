import asyncio
from pathlib import Path
from playwright.async_api import async_playwright

async def test_chatgpt():
    async with async_playwright() as p:
        context = await p.chromium.launch_persistent_context(
            user_data_dir=str(Path.home() / ".chatgpt_edge_profile"),
            headless=True,
            channel="msedge",
            chromium_sandbox=True,
        )
        page = context.pages[0] if context.pages else await context.new_page()
        await page.goto("https://chatgpt.com", wait_until="domcontentloaded")
        await asyncio.sleep(4)
        
        url = page.url
        print(f"[+] Current ChatGPT URL: {url}")
        
        textbox = page.locator("#prompt-textarea, div.ProseMirror[contenteditable='true'], div[contenteditable='true']").first
        try:
            await textbox.wait_for(state="visible", timeout=8000)
            print("[+] ChatGPT Textbox found!")
        except Exception as e:
            print("[-] ChatGPT Textbox not found:", e)
            title = await page.title()
            print(f"[-] Page title: {title}")
            
        await context.close()

if __name__ == "__main__":
    asyncio.run(test_chatgpt())
