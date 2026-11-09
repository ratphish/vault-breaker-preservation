import asyncio
import time
from pathlib import Path
from playwright.async_api import async_playwright

async def fetch():
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

        # Look for the chat link in recent chats
        links = await page.locator("a[href*='/app/']").all()
        target_link = None
        for l in links:
            t = await l.inner_text()
            if "Tiger Engine" in t or "ERROR COD" in t:
                target_link = l
                print(f"[+] Found conversation in list: {t}")
                break

        if target_link:
            await target_link.click()
            await asyncio.sleep(6)
        else:
            print("[-] Could not find link directly, checking url...")

        print("[+] Current URL:", page.url)

        # Wait until generation is finished (check every 3 seconds for up to 90 seconds)
        print("[*] Waiting for Argon answer to finish generating...")
        for attempt in range(30):
            await asyncio.sleep(3)
            # Check if stop button is gone and content length is substantial
            elements = await page.locator("message-content, .model-response-text, .response-container-content, div.markdown").all()
            for el in reversed(elements):
                txt = await el.inner_text()
                if len(txt) > 500 and "In Bungie's Tiger Engine" not in txt[:150]:
                    print(f"[+] Found finished response ({len(txt)} chars) at attempt {attempt}!")
                    with open(r"D:\vault-breaker-preservation\ARGON_SENIOR_ADVICE.md", "w", encoding="utf-8") as f:
                        f.write(txt)
                    await context.close()
                    return

        # If loop finishes without finding substantial block, dump innerText of main
        main = page.locator("main, div[role='main']").first
        if await main.is_visible():
            dump = await main.inner_text()
        else:
            dump = await page.inner_text("body")

        with open(r"D:\vault-breaker-preservation\ARGON_SENIOR_ADVICE.md", "w", encoding="utf-8") as f:
            f.write(dump)
        print("[+] Dumped text.")
        await context.close()

if __name__ == "__main__":
    asyncio.run(fetch())
