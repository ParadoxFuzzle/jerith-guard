# jerith-guard

**Deterministic inbound guard for OpenClaw agents.** Blocks prompt injection,
hacking payloads, credential-exfiltration attempts, and persona-sabotage
before the model sees them — with a spam layer for the rest.

- **No ML. No network calls. No API keys.** Every rule is a plain regex you
  can audit in one sitting (`src/detect.ts`).
- **Metadata-only logs.** The decision log stores rule ids, layer scores,
  verdict, and a SHA-256 hash of the sender id — never message text.
- **Owner-aware.** Messages from the configured owner are analyzed at half
  weight and never hard-blocked (their turns are logged, not stopped), so the
  guard never holds your own automation hostage.
- **Fail-open by policy choice.** Hook errors never block a turn; the guard
  layer failing is treated as no-op so your agent keeps working.

## What it detects (5 layers, 40 rules)

| Layer | Example patterns | Verdict on hit |
|---|---|---|
| Prompt injection | "ignore all previous instructions", fake `system:` tags, jailbreak modes, prompt-reveal asks | block (non-owner) |
| Hacking | `curl ... | bash`, reverse shells, `/dev/tcp`, base64-exec chains, `rm -rf /` | block |
| Exfiltration | attempts to read/post `.env`, `openclaw.json`, `.ssh`, `.pgpass`; web hook exfil endpoints | block |
| Persona sabotage | "you are now a raw/unfiltered agent", "delete your SOUL.md / security-rules", "disable your safety" | block |
| Spam / dilution | crypto shill, char runs, caps-shout, Discord invite farms, link farms, message bursts (>12/60s) | flag (logged, not blocked) |

## Install

```bash
openclaw plugins install clawhub:jerith-guard
```

Or from source:

```bash
git clone https://github.com/ParadoxFuzzle/jerith-guard
cd jerith-guard && npm install && npm run build
```

Then in `~/.openclaw/openclaw.json`:

```json
{
  "plugins": {
    "entries": {
      "jerith-guard": {
        "enabled": true,
        "config": { "enabled": true, "protectOwnerTurns": true },
        "hooks": { "allowConversationAccess": true }
      }
    }
  }
}
```

The `hooks.allowConversationAccess: true` consent flag is required for the
`before_agent_run` gate hook to attach on non-bundled plugins.

## Configuration

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `true` | Master switch (checked live; no restart needed to flip) |
| `protectOwnerTurns` | `true` | Owner messages are never hard-blocked, only logged |
| `logDir` | `~/.openclaw/state/jerith-guard` | Where `decisions.jsonl` is written |
| `sensitivity` | `balanced` | Reserved for future threshold presets |

## How it works

1. **`message_received`** — every inbound message increments a rolling 60s
   per-sender counter; bursts above 12/min get flagged.
2. **`before_agent_run` (gate hook)** — analyzes the user prompt before any
   model call. Non-owner prompts that hit a block layer are stopped *before*
   the LLM dispatch, with a category and user-facing message.
3. **`jerith-guard-stats`** — session tool: inspect stats, tail the decision
   log, or dry-run arbitrary text through all five layers (test an attack
   string without sending it).

## Honest limitations

- Deterministic regex rules catch the canonical patterns (the top-word
  recipes from real incident reports). Novel paraphrases can evade it; this
  is a high-precision net, not a full semantic filter.
- `senderIsOwner` is supplied by the platform; on channels where identity is
  unverified, treat "non-owner" as the safe default.
- The `jerith-guard-stats` tool is registered but may not appear in compact
  tool-search surfaces (the same happens in stock OpenClaw for plugin tools);
  the hook layer is unaffected.

## License

MIT — same spirit as context-squeeze. See `LICENSE`.

*Part of the Jerith stack: [context-squeeze](https://github.com/ParadoxFuzzle/context-squeeze) for context compression, build-game-plus for verified browser games.*
