#!/usr/bin/env python3
# Regenerates docs/assets/prompts-embed.js from docs/web/v1/prompts.json so the
# landing page renders every prompt instantly (no fetch, works on file:// too).
# Run after editing prompts.json:  python docs/build_prompts_embed.py
import json, os

HERE = os.path.dirname(os.path.abspath(__file__))
src = json.load(open(os.path.join(HERE, "web", "v1", "prompts.json"), encoding="utf-8"))

payload = {
    "version": src.get("version"),
    "modes": src.get("modes"),
    "types": src.get("types"),
    "prompts": src.get("prompts"),
    "deep_pack": src.get("deep_pack"),
}
out = os.path.join(HERE, "assets", "prompts-embed.js")
os.makedirs(os.path.dirname(out), exist_ok=True)
with open(out, "w", encoding="utf-8", newline="\n") as f:
    f.write("/* AUTO-GENERATED from docs/web/v1/prompts.json — run docs/build_prompts_embed.py. Do not edit by hand. */\n")
    f.write("window.AISA_PROMPTS = ")
    json.dump(payload, f, ensure_ascii=False, indent=0)
    f.write(";\n")
print("wrote", out, "(", len(payload["prompts"]), "prompts )")
