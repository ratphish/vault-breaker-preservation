import asyncio
from pathlib import Path
from playwright.async_api import async_playwright

async def read_chat():
    async with async_playwright() as p:
        context = await p.chromium.launch_persistent_context(
            user_data_dir=str(Path.home() / '.gemini_argon_profile'),
            headless=True,
            channel='msedge',
            chromium_sandbox=True,
        )
        page = context.pages[0] if context.pages else await context.new_page()
        await page.goto('https://gemini.google.com/app', wait_until='domcontentloaded')
        await asyncio.sleep(3)
        chat_link = page.locator("text='Marathon Tiger Engine Bootflow Halt'").first
        if await chat_link.is_visible(timeout=5000):
            await chat_link.click()
            await asyncio.sleep(5)
            # Find all model-response elements
            resps = await page.locator("model-response, .model-response-text, message-content, div.markdown").all_inner_texts()
            with open("D:/vault-breaker-preservation/ARGON_FULL_RESPONSE.md", "w", encoding="utf-8") as out:
                for idx, r in enumerate(resps):
                    out.write(f"=== Response {idx} ===\n{r}\n\n")
            print(f"[+] Dumped {len(resps)} response elements to ARGON_FULL_RESPONSE.md")
        else:
            print("[-] Could not find chat link")
        await context.close()

if __name__ == "__main__":
    asyncio.run(read_chat())
