# Benchmark results — v1.5.1 (fresh run, 2026-11-11)

Target: **OWASP Juice Shop** (source-only, read-only). Engine: **AISA CLI v1.5.1**, `init --profile auto` → `standard` (1,459 source files; jwt/llm/uploads signals). Scored against the frozen mechanical Core 30 / Full 60 — see [`core30.md`](core30.md) (selection rule) and [`juice-shop.labels.json`](juice-shop.labels.json) (per-challenge file + class answer key). Same rules for every tool.

- **Strict** = tool cited the right file **and** the right bug class → distinct challenge credited.
- **Coverage** = tool cited the right file (any class) → sibling challenges in that file credited.

| Tool | Core / 30 | Full / 60 strict | Full / 60 coverage | False positives | Time |
|---|---|---|---|---|---|
| **AISA CLI v1.5.1** | **25** | **46** | **53** | 0 | ~9 min (fresh run) |
| Codex (web, softer defensive prompt) | 11 | 23 | 46 | 0 | 18 min |
| Claude.ai (web, partial — ~40 routes, client-side not reached, 31% session usage) | 10 | 23 | 45 | 0 | 5 min |
| ChatGPT (web) | 7 | 18 | 48 | 0 | 22 min |
| Gemini 2.5 Pro (web) | — refused the task — | | | | — |
| **Web-AI union** | **14** | **29** | **53** | 0 | — |

## Honest reading

- On the frozen **Core 30**, the CLI (25) found more than **twice** any single web AI (7–11) and more than **all three web AIs combined** (14).
- On exact **Full-60** matches, the CLI (46) beats the **web-AI union** (29).
- On the looser **coverage** metric the field is close: CLI 53 vs web 45–48 (union 53). The engine's real advantage is **precision and completeness**, not reaching bugs the web AIs cannot.
- **False positives: 0** for every tool. Juice Shop is vulnerable by design, so there is little to falsely claim; real CLI findings outside the 60-challenge set (SSRF via profile-image URL, exposed premium/CTF keys, order-history IDOR, CSRF) are simply not counted, never penalised.

## CLI Core-30 misses (5, honest coverage gaps this run)

`aiDebuggingChallenge`, `chatbotPromptInjectionChallenge` — both in `routes/chat.ts`; the LLM/chatbot surface was not hunted in this run. `adminSectionChallenge` — client-side route guard. `reflectedXssChallenge` — `frontend/.../track-result` component. `ghostLoginChallenge` — deleted-user login via `routes/dataErasure.ts`.

## Caveats on the comparison

This is **not** a clean model-vs-model comparison: Claude.ai was partial, Codex used the softer defensive prompt, Gemini refused. The web-AI reports are the ones in `D:\bench\web-results` (`chatgpt.md`, `claude.docx`, `codex.md`); findings were extracted and each claim verified against the source before scoring. The CLI figure is a fresh end-to-end v1.5.1 run.
