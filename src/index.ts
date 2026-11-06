// index.ts — jerith-guard plugin entry.
//
// Deterministic guard layer for inbound messages:
//   • `message_received` — observes every inbound message, tracks per-sender
//     burst counts and verdict history (privacy: metadata only, no text).
//   • `before_agent_run` — GATE hook: analyzes the user prompt for prompt
//     injection, hacking payloads, credential exfiltration, persona
//     sabotage, and spam. Returns pass/block decision; block stops the run
//     before model dispatch. Owner messages get half-weight so owner
//     workflows are never blocked by their own tooling talk.
//   • `jerith-guard-stats` — dry-run tool: overall stats + analyze arbitrary
//     text against the rule layers without affecting live state.

import { defineToolPlugin } from "openclaw/plugin-sdk/tool-plugin";
import { textResult } from "openclaw/plugin-sdk/tool-results";
// `typebox` is a direct dependency of the OpenClaw runtime package, so the
// module resolves from the gateway's own node_modules chain inside plugin-load
// staging — no plugin-local copy needed (matches how capture staging resolves).
import { Type } from "typebox";
import { analyze, DEFAULT_LAYER_CONFIG, type LayerConfig } from "./detect.js";
import { GuardServer } from "./server.js";
import * as os from "node:os";
import * as path from "node:path";

type AnyApi = {
  on(event: string, handler: (...args: unknown[]) => Promise<unknown> | unknown): void;
  logger: { info: (s: string) => void; debug?: (s: string) => void; warn?: (s: string) => void };
  pluginConfig?: Record<string, unknown>;
};

let server: GuardServer | null = null;
let cfg: Required<LayerConfig> & { enabled: boolean; protectOwnerTurns: boolean; logDir: string } = {
  ...DEFAULT_LAYER_CONFIG,
  enabled: true,
  protectOwnerTurns: true,
  logDir: "",
};

function loadConfig(c: Record<string, unknown> | undefined) {
  if (!c) return;
  const num = (k: string, d: number) => {
    const raw = c[k];
    const n = typeof raw === "number" ? raw : Number(raw);
    // Clamp so a typo in config can't disable a layer (0/negative) or make it
    // unreachable (huge), which would silently turn the guard into a no-op.
    return Number.isFinite(n) ? Math.min(50, Math.max(1, n)) : d;
  };
  cfg.injectionThreshold = num("injectionThreshold", DEFAULT_LAYER_CONFIG.injectionThreshold);
  cfg.spamThreshold = num("spamThreshold", DEFAULT_LAYER_CONFIG.spamThreshold);
  cfg.hackingThreshold = num("hackingThreshold", DEFAULT_LAYER_CONFIG.hackingThreshold);
  cfg.exfilThreshold = num("exfilThreshold", DEFAULT_LAYER_CONFIG.exfilThreshold);
  cfg.impersonationThreshold = num("impersonationThreshold", DEFAULT_LAYER_CONFIG.impersonationThreshold);
  cfg.enabled = c.enabled !== false;
  cfg.protectOwnerTurns = c.protectOwnerTurns !== false;
  cfg.logDir = typeof c.logDir === "string" && c.logDir.trim() ? c.logDir.trim() : "";
  (cfg as unknown as Record<string, unknown>).sensitivity = c.sensitivity ?? "balanced";
}

const baseEntry = defineToolPlugin({
  id: "jerith-guard",
  name: "Jerith Guard",
  description:
    "Deterministic inbound guard: prompt-injection, hacking, exfiltration, persona-sabotage and spam detection on agent runs. No ML, no network, metadata-only logs.",
  configSchema: {
    type: "object",
    properties: {
      enabled: { type: "boolean", default: true },
      protectOwnerTurns: { type: "boolean", default: true },
      logDir: { type: "string", default: "" },
      sensitivity: { type: "string", enum: ["balanced", "strict", "relaxed"], default: "balanced" },
      injectionThreshold: { type: "number", minimum: 1, maximum: 50, default: 3 },
      spamThreshold: { type: "number", minimum: 1, maximum: 50, default: 3 },
      hackingThreshold: { type: "number", minimum: 1, maximum: 50, default: 3 },
      exfilThreshold: { type: "number", minimum: 1, maximum: 50, default: 3 },
      impersonationThreshold: { type: "number", minimum: 1, maximum: 50, default: 3 },
    },
    additionalProperties: false,
  },
  tools: (tool) => [
    tool({
      name: "jerith-guard-stats",
      description:
        "Inspect jerith-guard: live tracked-sender stats, recent decision log (metadata only), plus an optional dry-run analysis of arbitrary text against all detection layers. Never modifies live state.",
      parameters: Type.Object({
        sampleText: Type.Optional(Type.String({ description: "Optional text to dry-run through all detection layers." })),
        senderIsOwner: Type.Optional(Type.Boolean({ description: "Treat the dry-run text as from the owner (default false)." })),
      }),
      execute: async ({ sampleText, senderIsOwner }) => {
        if (!server) return textResult("jerith-guard server not initialized (plugin not registered yet).", { ok: false });
        const lines = ["— jerith-guard live stats —", server.stats(), ""];
        const recent = server.tailLog(10);
        if (recent.length) {
          lines.push("— recent decisions (metadata only) —");
          for (const line of recent) {
            try {
              const rec = JSON.parse(line);
              lines.push(`${rec.at} ${rec.verdict.toUpperCase()} layers=${(rec.layers || []).join(",") || "none"} threats=${rec.threatScore} msgs60s=${rec.recentCount60s}`);
            } catch { lines.push(line.slice(0, 120)); }
          }
          lines.push("");
        }
        if (sampleText && sampleText.trim()) {
          const a = analyze(
            {
              text: sampleText,
              senderIsOwner: senderIsOwner === true,
              isFirstContact: false,
              senderRecentCount: 0,
            },
            cfg
          );
          lines.push(`— dry-run verdict: ${a.action.toUpperCase()} —`);
          for (const [layer, hit] of Object.entries(a.layers)) {
            if (hit.matches.length) lines.push(`  ${layer}: score=${hit.score} rules=${hit.matches.join(",")}`);
          }
          if (!Object.values(a.layers).some((h) => h.matches.length)) lines.push("  (no layer triggered)");
        }
        return textResult(lines.join("\n").trim(), { ok: true });
      },
    }),
  ],
});

type GateApi = Parameters<typeof baseEntry["register"]>[0];

// Wrap register() ON the baseEntry object itself — spreading into a new object
// loses the non-enumerable tool-plugin metadata symbol that `openclaw plugins
// validate` requires (same bug shape context-squeeze hit originally).
const toolRegister = baseEntry.register.bind(baseEntry);
baseEntry.register = (api: GateApi) => {
    const pluginConfig = (api as unknown as { pluginConfig?: Record<string, unknown> }).pluginConfig;
    loadConfig(pluginConfig);

    // Portable default: never bake an absolute home path into a published plugin.
    const stateDir = cfg.logDir ? expandHome(cfg.logDir) : path.join(os.homedir(), ".openclaw", "state", "jerith-guard");
    server = new GuardServer(stateDir);

    api.logger.info(
      `jerith-guard armed: enabled=${cfg.enabled} thresholds(inj=${cfg.injectionThreshold},spam=${cfg.spamThreshold},hack=${cfg.hackingThreshold},exfil=${cfg.exfilThreshold},imp=${cfg.impersonationThreshold}) logDir=${stateDir}`
    );

    // 1) Observe inbound messages for sender burst counting + verdict history.
    const onMsg = api.on as unknown as (ev: string, h: (...args: unknown[]) => unknown) => void;
    onMsg("message_received", (event: unknown) => {
      if (!cfg.enabled || !server) return;
      const e = event as {
        content?: string;
        senderId?: string;
        senderIsOwner?: boolean;
        sessionKey?: string;
      };
      if (!e || typeof e.content !== "string") return;
      const senderId = String(e.senderId ?? "unknown");
      const recent = server.recentCount(senderId);
      if (recent > 12 && !(e.senderIsOwner === true)) {
        server.recordVerdict(senderId, "flag", ["spam.burst"]);
        (api.logger.warn ?? api.logger.info).call(
          api.logger,
          `jerith-guard: sender ${server.senderTag(senderId)} burst=${recent}/60s — flagged`
        );
      }
      return undefined;
    });

    // 2) Gate every agent run: analyze the user prompt before any model call.
    onMsg("before_agent_run", (event: unknown, ctx: unknown) => {
      if (!cfg.enabled || !server) return undefined;
      const e = event as {
        prompt?: string;
        senderId?: string;
        senderIsOwner?: boolean;
        channelId?: string;
      };
      if (!e || typeof e.prompt !== "string" || !e.prompt.trim()) return undefined;
      const c = (ctx ?? {}) as { trigger?: string };
      if (c.trigger && c.trigger !== "user") return undefined; // skip heartbeat/cron turns

      const senderId = String(e.senderId ?? "unknown");
      const isOwner = e.senderIsOwner === true;
      // countRecent() only reads. recentCount() INCREMENTS the 60s window, so
      // calling it here would double-count every run on top of message_received
      // and flag senders at half the real threshold.
      const recentCount = server.countRecent(senderId);
      const a = analyze(
        {
          text: e.prompt,
          senderIsOwner: isOwner,
          isFirstContact: server.isFirstContact(senderId),
          senderRecentCount: recentCount,
        },
        cfg
      );

      server.recordVerdict(senderId, a.action, a.triggered);

      if (a.action === "block" && (!isOwner || !cfg.protectOwnerTurns)) {
        (api.logger.warn ?? api.logger.info).call(
          api.logger,
          `jerith-guard BLOCK sender=${server.senderTag(senderId)} layers=${a.triggered.join(",")} rules=${Object.values(a.layers).flatMap((h) => h.matches).join(",")}`
        );
        return {
          decision: {
            outcome: "block" as const,
            reason: `jerith-guard: ${a.triggered.join("+")}`,
            message:
              "Blocked by jerith-guard (deterministic guard layer). Your message matched patterns for: " +
              a.triggered.join(", ") +
              ". If this is a false positive, contact the operator (ParadoxFuzzle).",
            category: a.triggered[0] ?? "guard",
          },
        };
      }
      if (a.action === "flag") {
        (api.logger.info).call(
          api.logger,
          `jerith-guard flag sender=${server.senderTag(senderId)} layers=${a.triggered.join(",")}`
        );
      } else if (isOwner && a.triggered.length) {
        api.logger.debug?.(
          `jerith-guard owner turn matched rules (halved weight, allowed): ${Object.values(a.layers).flatMap((h) => h.matches).join(",")}`
        );
      }
      return undefined; // pass (or flag: logged only)
    });

    // 3) Expose the dry-run stats tool.
    toolRegister(api);
  };

function expandHome(p: string): string {
  if (p === "~") return os.homedir();
  if (p.startsWith("~/")) return path.join(os.homedir(), p.slice(2));
  return p;
}

export default baseEntry;
