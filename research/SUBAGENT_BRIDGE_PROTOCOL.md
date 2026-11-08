# Antigravity Sub-Agent Bridge Protocol: Argon & ChatGPT (Edge)

This protocol documents the automated CLI bridge (`ask_argon.py`) that delegates complex reverse-engineering roadblocks, memory fixups, and architectural analyses to external reasoning models via persistent Microsoft Edge sessions:
- **Argon (Gemini 4 Argon)**: Primary agent for engine layout reconstruction, binary reverse engineering, and state machine analysis.
- **ChatGPT**: Secondary agent for logic validation, consensus cross-checking, and code verification.

---

## 1. Interactive Session Setup (One-Time / As Needed)
If a session expires or returns an authentication error, the user initializes the persistent profile:
- Setup Argon profile:
  `python ask_argon.py --login --target argon`
- Setup ChatGPT profile:
  `python ask_argon.py --login --target chatgpt`

---

## 2. Available CLI Commands & Flags

### A. Query Argon (Default)
Packages the handoff and queries Gemini 4 Argon:
```powershell
python ask_argon.py -f ARGON_HANDOFF.md --target argon
```
* **Output**: Automatically written to `ARGON_SOLUTION.md`.

### B. Query ChatGPT
Packages the handoff and queries ChatGPT:
```powershell
python ask_argon.py -f ARGON_HANDOFF.md --target chatgpt
```
* **Output**: Automatically written to `CHATGPT_SOLUTION.md`.

### C. Parallel Dual-Agent Execution (Recommended for Roadblocks)
Spawns both models concurrently in separate browser contexts to compare recommendations:
```powershell
python ask_argon.py -f ARGON_HANDOFF.md --target both
```
* **Outputs**: Concurrently writes to both `ARGON_SOLUTION.md` and `CHATGPT_SOLUTION.md`.

---

## 3. Agent Execution Workflow for Antigravity

When encountering an emulation crash, dynamic branch redirection, or unmapped structure during reverse engineering:

1. **Generate Handoff Markdown:**
   * Dump the exact register state, faulting instruction RVA, stack contents, and relevant memory ranges into `ARGON_HANDOFF.md`.
   * Frame concrete architectural questions (e.g., target subsystem identity, expected structure layout, return conventions).

2. **Invoke the Sub-Agent Bridge:**
   * Run `python ask_argon.py -f ARGON_HANDOFF.md --target both`.

3. **Synthesize & Cross-Check Solutions:**
   * Read `ARGON_SOLUTION.md` and `CHATGPT_SOLUTION.md`.
   * Identify points of mutual agreement (offsets, struct sizes, hook locations).
   * If there is divergence, favor the analysis backed by verified register semantics and disassembly traces.

4. **Apply & Verify:**
   * Implement the fixup hooks or memory buffers in `scripts/emulate_synthetic_function.py`.
   * Execute the test suite (`pytest tests/`) to ensure all assertions pass without regression.
