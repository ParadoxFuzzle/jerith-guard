// server.ts — per-sender state + persistence for jerith-guard.
//
// Tracks:
//   • rolling 60s message counter per senderId (burst/spam detection)
//   • per-sender verdict history (bad-actor scoring: consecutive blocks raise
//     the actor's persistence score; decay when they behave)
//   • decision log (JSONL) — metadata only: rule ids, layer scores,
//     verdict, senderId hash. NEVER raw message text. Privacy by design.

import * as fs from "node:fs";
import * as path from "node:path";
import * as crypto from "node:crypto";

export const MAX_DECISION_LOG_BYTES = 2 * 1024 * 1024;
const LOG_TRIM_TARGET_BYTES = Math.floor(MAX_DECISION_LOG_BYTES * 0.75);

export interface SenderState {
  messageTimestamps: number[];
  verdicts: { at: number; action: string; layers: string[] }[];
  threatScore: number;
  firstSeenAt: number;
  lastSeenAt: number;
  lastVerdictAt: number;
}

export class GuardServer {
  private state = new Map<string, SenderState>();
  private logPath: string;
  private readonly windowMs = 60_000;

  constructor(stateDir: string) {
    this.logPath = path.join(stateDir, "decisions.jsonl");
    try {
      fs.mkdirSync(path.dirname(this.logPath), { recursive: true });
      if (fs.existsSync(this.logPath)) {
        fs.chmodSync(this.logPath, 0o600);
        this.trimLogIfNeeded();
      }
    } catch { /* best-effort */ }
  }

  /** Read-only 60s count for the gate: must not record a new message. */
  countRecent(senderId: string, now = Date.now()): number {
    const s = this.state.get(senderId);
    if (!s) return 0;
    // Read-only from the caller's perspective, but prune expired timestamps in
    // place so a long-lived sender cannot grow this array without bound.
    s.messageTimestamps = s.messageTimestamps.filter((t) => now - t < this.windowMs);
    return s.messageTimestamps.length;
  }

  isFirstContact(senderId: string): boolean {
    const s = this.state.get(senderId);
    return !s || s.verdicts.length === 0;
  }

  /** Stable, non-reversible sender tag for logs; never the raw platform id. */
  senderTag(senderId: string): string {
    return this.hash(senderId).slice(0, 8);
  }

  recentCount(senderId: string, now = Date.now()): number {
    const s = this.get(senderId, now);
    s.messageTimestamps = s.messageTimestamps.filter((t) => now - t < this.windowMs);
    s.messageTimestamps.push(now);
    s.lastSeenAt = now;
    return s.messageTimestamps.length;
  }

  recordVerdict(senderId: string, action: string, layers: string[], now = Date.now()) {
    const s = this.get(senderId, now);
    s.verdicts.push({ at: now, action, layers });
    if (s.verdicts.length > 200) s.verdicts = s.verdicts.slice(-200);
    // Decay measured from the previous VERDICT, not the last inbound message:
    // message_received stamps lastSeenAt immediately before every gated turn,
    // so using it here would reset the decay window on every message.
    const daysSince = Math.max(0, (now - s.lastVerdictAt) / 86_400_000);
    s.threatScore = Math.max(0, s.threatScore * Math.pow(0.9, daysSince));
    s.lastSeenAt = now;
    s.lastVerdictAt = now;
    if (action === "block") s.threatScore += 2;
    else if (action === "flag") s.threatScore += 0.5;
    this.appendLog({
      at: new Date(now).toISOString(),
      senderHash: this.hash(senderId),
      isFirstContact: s.verdicts.length === 1,
      verdict: action,
      layers,
      threatScore: Math.round(s.threatScore * 100) / 100,
      recentCount60s: s.messageTimestamps.length,
    });
  }

  isFlaggedActor(senderId: string): boolean {
    const s = this.state.get(senderId);
    return !!s && s.threatScore >= 4;
  }

  threatScore(senderId: string): number {
    return this.state.get(senderId)?.threatScore ?? 0;
  }

  snapshot(): { tracked: number; flagged: number; logExists: boolean } {
    let flagged = 0;
    for (const s of this.state.values()) if (s.threatScore >= 4) flagged++;
    return { tracked: this.state.size, flagged, logExists: fs.existsSync(this.logPath) };
  }

  tailLog(lines = 20): string[] {
    try {
      const raw = fs.readFileSync(this.logPath, "utf8");
      const all = raw.trim().split("\n").filter(Boolean);
      return all.slice(-lines);
    } catch {
      return [];
    }
  }

  stats(): string {
    const snap = this.snapshot();
    const flaggedIds = [...this.state.entries()].filter(([, s]) => s.threatScore >= 4).length;
    let total = 0, blocked = 0, flagged = 0;
    try {
      const all = fs.readFileSync(this.logPath, "utf8").trim().split("\n").filter(Boolean);
      for (const line of all) {
        try {
          const rec = JSON.parse(line);
          total++;
          if (rec.verdict === "block") blocked++;
          if (rec.verdict === "flag") flagged++;
        } catch { /* skip bad lines */ }
      }
    } catch { /* no log yet */ }
    return [
      `tracked senders: ${snap.tracked} (flagged actors: ${flaggedIds})`,
      `decisions in retained log: ${total} — ${blocked} blocked, ${flagged} flagged`,
      `decision log at: ${this.logPath} (metadata only, no message text)`,
    ].join("\n");
  }

  private get(senderId: string, now = Date.now()): SenderState {
    let s = this.state.get(senderId);
    if (!s) {
      s = { messageTimestamps: [], verdicts: [], threatScore: 0, firstSeenAt: now, lastSeenAt: now, lastVerdictAt: now };
      this.state.set(senderId, s);
    }
    return s;
  }

  private hash(id: string): string {
    return crypto.createHash("sha256").update(id).digest("hex").slice(0, 16);
  }

  private appendLog(obj: unknown) {
    try {
      fs.appendFileSync(this.logPath, JSON.stringify(obj) + "\n", { mode: 0o600 });
      this.trimLogIfNeeded();
    } catch { /* best-effort */ }
  }

  /** Keep the JSONL log bounded; trim the oldest complete records when full. */
  private trimLogIfNeeded() {
    const size = fs.statSync(this.logPath).size;
    if (size <= MAX_DECISION_LOG_BYTES) return;

    const buf = fs.readFileSync(this.logPath);
    const keepFrom = Math.max(0, size - LOG_TRIM_TARGET_BYTES);
    const newline = buf.indexOf(0x0a, keepFrom);
    const kept = newline >= 0 ? buf.subarray(newline + 1) : Buffer.alloc(0);
    const tmp = `${this.logPath}.${process.pid}.tmp`;
    try {
      fs.writeFileSync(tmp, kept, { mode: 0o600 });
      fs.renameSync(tmp, this.logPath);
    } finally {
      try { fs.rmSync(tmp, { force: true }); } catch { /* noop */ }
    }
  }
}
