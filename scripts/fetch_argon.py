import asyncio
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
        await page.goto("https://gemini.google.com/app/e44768a1cb151cb4", wait_until="domcontentloaded")
        await asyncio.sleep(5)

        # Wait for messages to render
        await asyncio.sleep(4)
        
        # Now find model response
        responses = await page.locator("message-content, .model-response-text, .response-container-content, div.markdown").all()
        print(f"Found {len(responses)} candidate elements")
        
        extracted = []
        for r in responses:
            t = await r.inner_text()
            if len(t) > 100:
                extracted.append(t)
                
        if extracted:
            print(f"[+] Extracted {len(extracted)} response blocks.")
            full_text = "\n\n---\n\n".join(extracted)
            with open(r"D:\vault-breaker-preservation\ARGON_STINGRAY_RESPONSE.md", "w", encoding="utf-8") as f:
                f.write(full_text)
            print("[+] Written to ARGON_STINGRAY_RESPONSE.md successfully!")
        else:
            print("[-] No candidate elements, dumping inner_text of body...")
            body_txt = await page.inner_text("body")
            with open(r"D:\vault-breaker-preservation\ARGON_STINGRAY_RESPONSE.md", "w", encoding="utf-8") as f:
                f.write(body_txt)
            print("[+] Dumped body text.")

        await context.close()

if __name__ == "__main__":
    asyncio.run(fetch())
