import asyncio
import os
from pathlib import Path
from playwright.async_api import async_playwright

PROMPT = """You are a senior reverse engineer specializing in Bungie's Tiger Engine (Destiny 2, Marathon Build 26136895, version 248199.26.10.21.2300.gol_retail.rc).

We are building a standalone offline emulator/preservation proxy (Project Dawn / Sunrise architecture) for Marathon's PvE activity "Vault Breaker" (Cryo Archive).

### Current Situation:
1. The game boots past media check, bootload, shader precompilation, and renders the Press Enter / Sign-In title screen.
2. In our custom `steam_api64.dll` proxy:
   - We emulate ISteamClient021, ISteamUser023, ISteamUtils010, ISteamApps008, ISteamFriends017, ISteamInput006.
   - `SteamUser023::BLoggedOn()` returns 1.
   - `SteamUser023::GetSteamID()` returns `76561198000001001` via hidden struct pointer (MSVC ABI).
   - `SteamUser023::GetAuthSessionTicket()` returns ticket handle 1.
   - `SteamUser023::RequestEncryptedAppTicket()` (slot 21) registers callback 154 (`EncryptedAppTicketResponse_t`) and dispatches `k_EResultOK`.
   - `SteamUser023::GetEncryptedAppTicket()` (slot 22) returns 128 bytes synthetic ticket.
   - In `SteamAPI_RunCallbacks()`, we dispatch:
     - Callback 101 (`SteamServersConnected_t`)
     - Callback 154 (`EncryptedAppTicketResponse_t`)
     - Callback 304 (`AvatarImageLoaded_t`)
     - Callback 337 (`PersonaStateChange_t`)
     - Callback 1101 (`UserStatsReceived_t`)
3. When the user presses Enter on the title screen, the client attempts to sign in, but then displays:
   "ERROR: Could not sign in to Marathon servers. Please try again later. For more information, visit help.bungie.net and search for error code: stingray"
   And `SteamAPI_Shutdown` is called.

### Official Bungie Definition:
In Destiny 2 and Bungie games, "ERROR CODE: STINGRAY" explicitly indicates that the platform account (Steam / Xbox / PSN) is not signed in or platform authentication failed. (Whereas "YAM" is ticket generation failure).

### Questions for Senior Engine Experts:
1. Did the Project Dawn / Sunrise team run into `ERROR CODE: STINGRAY` in Destiny 2 / Marathon emulation? What was the exact root cause?
2. What specific Steam API interface methods, vtable slots, or callbacks does Tiger Engine check to verify the Steam platform account is signed in before or during the SignOn request?
   - Is it looking for `GetAuthSessionTicketResponse_t` (callback 163)?
   - Is it looking for `ValidateAuthTicketResponse_t` (callback 143)?
   - Is it looking for a specific return code from `SteamUser()->GetAuthSessionTicket()`?
   - Does it check `SteamUser()->UserHasLicenseForApp()` (slot 12)?
3. What is the exact sequence of events between pressing Enter on the title screen and dispatching the HTTP POST to `https://signon.goliath.prod.deadorbit.net/SignOn`? How did Project Dawn ensure the client proceeds seamlessly from title screen into BAP activity allocation?

Please provide concrete, actionable technical advice and C++/Python implementations.
"""

async def run_consultation():
    print("[*] Launching browser for Argon consultation...")
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
        print("[+] Gemini/Argon text area found.")

        # Click New Chat to avoid polluting conversation
        try:
            new_chat = page.locator("a[aria-label*='New chat' i], button[aria-label*='New chat' i]").first
            if await new_chat.is_visible(timeout=3000):
                await new_chat.click()
                await asyncio.sleep(2)
                print("[+] Clicked New Chat.")
        except Exception as e:
            print("[-] New chat click warning:", e)

        # Paste prompt into text area
        await textbox.click()
        await page.evaluate("""(text) => {
            const el = document.querySelector("div[contenteditable='true'], rich-textarea div.ql-editor");
            if (el) {
                el.focus();
                document.execCommand('insertText', false, text);
            }
        }""", PROMPT)
        await asyncio.sleep(2)

        send_btn = page.locator("button[aria-label*='Send' i], button.send-button").first
        await send_btn.wait_for(state="visible", timeout=5000)
        await send_btn.click()
        print("[+] Prompt sent to Argon! Waiting for streaming response...")

        # Wait for response generation to start and finish
        await asyncio.sleep(8)
        
        # Poll for completion (e.g. stop button disappears or model response settles)
        for i in range(30): # up to 60 seconds
            await asyncio.sleep(2)
            # Check if stop button is present
            stop_btn = page.locator("button[aria-label*='Stop' i]").first
            is_generating = await stop_btn.is_visible() if await stop_btn.count() > 0 else False
            if not is_generating and i > 3:
                print(f"[+] Generation complete after ~{(i+4)*2} seconds.")
                break
        
        # Extract last response text
        responses = page.locator("message-content, div.model-response-text, .markdown").all()
        last_resp = None
        for r in await responses:
            t = await r.inner_text()
            if len(t) > 200:
                last_resp = t
                
        if last_resp:
            print(f"[+] Received Argon response ({len(last_resp)} characters)!")
            with open(r"D:\vault-breaker-preservation\ARGON_STINGRAY_RESPONSE.md", "w", encoding="utf-8") as out:
                out.write(last_resp)
            print("[+] Saved to D:\\vault-breaker-preservation\\ARGON_STINGRAY_RESPONSE.md")
        else:
            # Fallback: dump all page text
            all_text = await page.inner_text("body")
            with open(r"D:\vault-breaker-preservation\ARGON_STINGRAY_RESPONSE.md", "w", encoding="utf-8") as out:
                out.write(all_text)
            print("[+] Saved body text fallback.")

        await context.close()

if __name__ == "__main__":
    asyncio.run(run_consultation())
