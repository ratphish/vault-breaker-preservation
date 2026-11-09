import asyncio
from pathlib import Path
from playwright.async_api import async_playwright

async def test_input():
    async with async_playwright() as p:
        context = await p.chromium.launch_persistent_context(
            user_data_dir=str(Path.home() / ".gemini_argon_profile"),
            headless=True,
            channel="msedge",
            chromium_sandbox=True,
        )
        page = context.pages[0] if context.pages else await context.new_page()
        await page.goto("https://gemini.google.com/app", wait_until="domcontentloaded")
        await asyncio.sleep(4)
        
        textbox = page.locator("div[contenteditable='true'], rich-textarea div.ql-editor").first
        await textbox.wait_for(state="visible", timeout=15000)
        print("[+] Textbox found")
        
        # Click new chat if available
        try:
            new_chat = page.locator("a[aria-label*='New chat' i], button[aria-label*='New chat' i]").first
            if await new_chat.is_visible(timeout=3000):
                await new_chat.click()
                await asyncio.sleep(2)
                print("[+] Clicked New Chat")
        except Exception as e:
            print("[-] New chat click:", e)
            
        await textbox.click()
        # Paste via clipboard or keyboard insert
        await page.evaluate("""(text) => {
            const el = document.querySelector("div[contenteditable='true'], rich-textarea div.ql-editor");
            if (el) {
                el.focus();
                document.execCommand('insertText', false, text);
            }
        }""", "Hello from test input")
        await asyncio.sleep(1)
        
        send_btn = page.locator("button[aria-label*='Send' i], button.send-button").first
        vis = await send_btn.is_visible()
        enabled = await send_btn.is_enabled() if vis else False
        print(f"[+] Send button: visible={vis}, enabled={enabled}")
        
        await context.close()

if __name__ == "__main__":
    asyncio.run(test_input())
