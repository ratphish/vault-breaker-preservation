import asyncio
from pathlib import Path
from playwright.async_api import async_playwright

PROMPT = """In game engine architecture (specifically Bungie's Tiger Engine for Destiny 2 / Marathon) and Steamworks C++ SDK integration:

What causes ERROR CODE: STINGRAY vs ERROR CODE: YAM during platform sign-on?

We are working on software preservation / offline compatibility for an unreleased archive build (similar to the open-source Project Dawn / Project Sunrise research for Destiny 2).

Current status:
1. Game boots past media check, bootload, shader precompilation, and renders the Press Enter title screen.
2. In our Steamworks SDK compatibility layer (steam_api64.dll):
   - ISteamClient021, ISteamUser023, ISteamUtils010, ISteamApps008, ISteamFriends017, ISteamInput006 are provided.
   - BLoggedOn() returns 1.
   - GetSteamID() returns a 64-bit Steam ID.
   - GetAuthSessionTicket() returns ticket handle 1.
   - When RequestEncryptedAppTicket() is called, EncryptedAppTicketResponse_t (callback 154) is dispatched with k_EResultOK, and GetEncryptedAppTicket() returns 128 bytes.
   - In SteamAPI_RunCallbacks(), callback 101 (SteamServersConnected_t), 154, 304, 337, and 1101 are dispatched.
3. When the user presses Enter on the title screen, the client says "Signing in..." and then fails with:
   "ERROR: Could not sign in to Marathon servers. Please try again later. For more information, visit help.bungie.net and search for error code: stingray"
   (or sometimes error code "yam", Additional information: 0:41).

Questions:
1. In Bungie's platform sign-in state machine, what exact conditions trigger STINGRAY vs YAM?
   - What specific Steamworks callbacks or API methods does the engine check? (e.g., GetAuthSessionTicketResponse_t callback 163, ValidateAuthTicketResponse_t callback 143, UserHasLicenseForApp slot 12, or specific return values from GetAuthSessionTicket)?
2. Did open source preservation projects like Project Dawn or Project Sunrise document encountering STINGRAY and YAM? What were the root causes and resolutions?
3. What is the exact sequence of events between pressing Enter on the title screen and the client dispatching the HTTPS POST /SignOn request to the server?
"""

async def run():
    print("[*] Launching Edge (headless=False) for ChatGPT consultation...")
    async with async_playwright() as p:
        context = await p.chromium.launch_persistent_context(
            user_data_dir=str(Path.home() / ".chatgpt_edge_profile"),
            headless=False,
            channel="msedge",
        )
        page = context.pages[0] if context.pages else await context.new_page()
        await page.goto("https://chatgpt.com", wait_until="domcontentloaded")
        await asyncio.sleep(6)

        print("[+] URL:", page.url)
        print("[+] Title:", await page.title())

        # Check if Cloudflare or textbox
        textbox = page.locator("#prompt-textarea, div.ProseMirror[contenteditable='true'], div[contenteditable='true']").first
        try:
            await textbox.wait_for(state="visible", timeout=12000)
            print("[+] Textbox found! Typing prompt...")
            await textbox.click()
            await page.evaluate("""(text) => {
                const el = document.querySelector("#prompt-textarea, div.ProseMirror[contenteditable='true'], div[contenteditable='true']");
                if (el) {
                    el.focus();
                    document.execCommand('insertText', false, text);
                }
            }""", PROMPT)
            await asyncio.sleep(1)

            send_btn = page.locator("button[data-testid='send-button'], button[aria-label*='Send' i]").first
            await send_btn.wait_for(state="visible", timeout=5000)
            await send_btn.click()
            print("[+] Prompt sent to ChatGPT! Waiting for completion...")

            # Wait for response to generate
            await asyncio.sleep(15)
            for i in range(40):
                await asyncio.sleep(2)
                # Check if stop button is gone
                stop_btn = page.locator("button[data-testid='stop-button'], button[aria-label*='Stop' i]").first
                is_gen = await stop_btn.is_visible() if await stop_btn.count() > 0 else False
                if not is_gen and i > 5:
                    print(f"[+] ChatGPT finished generating after {(i+5)*2}s.")
                    break

            # Extract response
            responses = await page.locator("div.markdown, div[data-message-author-role='assistant']").all()
            if responses:
                last_txt = await responses[-1].inner_text()
                with open(r"D:\vault-breaker-preservation\CHATGPT_SENIOR_ADVICE.md", "w", encoding="utf-8") as f:
                    f.write(last_txt)
                print(f"[+] Saved ChatGPT response ({len(last_txt)} characters) to CHATGPT_SENIOR_ADVICE.md!")
            else:
                body = await page.inner_text("body")
                with open(r"D:\vault-breaker-preservation\CHATGPT_SENIOR_ADVICE.md", "w", encoding="utf-8") as f:
                    f.write(body)
                print("[+] Saved body text.")

        except Exception as e:
            print("[-] Exception:", e)
            body = await page.inner_text("body")
            print("[-] Body preview:", body[:300])

        await context.close()

if __name__ == "__main__":
    asyncio.run(run())
