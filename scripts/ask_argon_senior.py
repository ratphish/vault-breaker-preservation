import asyncio
from pathlib import Path
from playwright.async_api import async_playwright

PROMPT = """In Bungie's Tiger Engine (Destiny 2 and Marathon engine architecture) and Steamworks C++ SDK integration:

What causes ERROR CODE: STINGRAY vs ERROR CODE: YAM during player sign-on?

We are researching Tiger Engine platform authentication and archival compatibility (similar to the Project Dawn and Project Sunrise archival research projects for Destiny 2).

Currently:
1. The client loads, initializes Steamworks, and reaches the title screen ("Press Enter").
2. In our Steamworks compatibility layer (steam_api64):
   - ISteamClient021, ISteamUser023, ISteamUtils010, ISteamApps008, ISteamFriends017, ISteamInput006 are provided.
   - BLoggedOn() returns true.
   - GetSteamID() returns valid 64-bit Steam ID.
   - GetAuthSessionTicket() returns ticket handle 1.
   - When RequestEncryptedAppTicket() is called, EncryptedAppTicketResponse_t (callback 154) is dispatched with k_EResultOK, and GetEncryptedAppTicket() returns a synthetic ticket.
   - In SteamAPI_RunCallbacks(), callback 101 (SteamServersConnected_t), 154, 304, 337, and 1101 are dispatched.
3. When pressing Enter, the client briefly says "Signing in..." and then fails with:
   "ERROR: Could not sign in to Marathon servers. Error code: stingray"
   (or sometimes error code "yam", Additional information: 0:41).

Questions for senior engine / platform systems engineers:
1. In Tiger Engine's platform sign-in state machine, what exact condition triggers STINGRAY vs YAM?
   - What specific Steamworks callbacks or API methods does the engine wait on? (e.g., GetAuthSessionTicketResponse_t callback 163, ValidateAuthTicketResponse_t callback 143, UserHasLicenseForApp slot 12, or specific return values from GetAuthSessionTicket)?
2. Did the Project Dawn / Project Sunrise engineers encounter STINGRAY or YAM during Destiny 2 / Marathon standalone server bringup, and what was the resolution?
3. What is the exact sequence of checks between the title screen input and the client issuing the HTTPS POST /SignOn request to the server?

Please explain the technical details and provide the required Steamworks C++ implementation and callback structures.
"""

async def run():
    print("[*] Launching Edge to consult Argon...")
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

        # Click New Chat
        try:
            new_chat = page.locator("a[aria-label*='New chat' i], button[aria-label*='New chat' i]").first
            if await new_chat.is_visible(timeout=3000):
                await new_chat.click()
                await asyncio.sleep(2)
                print("[+] Clicked New Chat.")
        except Exception as e:
            print("[-] Note on new chat:", e)

        textbox = page.locator("div[contenteditable='true'], rich-textarea div.ql-editor").first
        await textbox.wait_for(state="visible", timeout=10000)
        await textbox.click()

        # Insert text
        await page.evaluate("""(text) => {
            const el = document.querySelector("div[contenteditable='true'], rich-textarea div.ql-editor");
            if (el) {
                el.focus();
                document.execCommand('insertText', false, text);
            }
        }""", PROMPT)
        await asyncio.sleep(1)

        send_btn = page.locator("button[aria-label*='Send' i], button.send-button").first
        await send_btn.wait_for(state="visible", timeout=5000)
        await send_btn.click()
        print("[+] Prompt sent to Argon! Waiting for streaming response...")

        # Wait for generation to start
        await asyncio.sleep(10)

        # Poll until complete (up to 90 seconds)
        for i in range(45):
            await asyncio.sleep(2)
            stop_btn = page.locator("button[aria-label*='Stop' i]").first
            is_generating = await stop_btn.is_visible() if await stop_btn.count() > 0 else False
            if not is_generating and i > 4:
                print(f"[+] Generation settled after {(i+5)*2}s.")
                break

        await asyncio.sleep(3)
        responses = await page.locator("message-content, .model-response-text, .response-container-content, div.markdown").all()
        print(f"[+] Found {len(responses)} candidate response blocks.")

        extracted = None
        for r in reversed(responses):
            txt = await r.inner_text()
            if len(txt) > 300 and "Bungie's Tiger Engine" not in txt[:150]:
                extracted = txt
                break

        if extracted:
            print(f"[+] SUCCESS! Extracted Argon response ({len(extracted)} characters).")
            with open(r"D:\vault-breaker-preservation\ARGON_SENIOR_ADVICE.md", "w", encoding="utf-8") as f:
                f.write(extracted)
        else:
            print("[-] Falling back to body text.")
            body_txt = await page.inner_text("body")
            with open(r"D:\vault-breaker-preservation\ARGON_SENIOR_ADVICE.md", "w", encoding="utf-8") as f:
                f.write(body_txt)

        await context.close()

if __name__ == "__main__":
    asyncio.run(run())
