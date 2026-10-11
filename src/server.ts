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

export interface SenderState {
  messageTimestamps: number[];
  verdicts: { at: number; action: string; layers: string[] }[];
  threatScore: number;
  firstSeenAt: number;
  lastSeenAt: number;
}

export class GuardServer {
  private state = new Map<string, SenderState>();
  private logPath: string;
  private readonly windowMs = 60_000;

  constructor(stateDir: string) {
    this.logPath = path.join(stateDir, "decisions.jsonl");
    try { fs.mkdirSync(path.dirname(this.logPath), { recursive: true }); } catch { /* noop */ }
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
    const decay = 0.97;
    const daysSince = (now - s.lastSeenAt) / (24 * 3600 * 1000);
    s.threatScore = Math.max(0, s.threatScore * Math.pow(decay, daysSince * 24));
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
      `tracked senders: ${snap.tracked} (flagged actors: ${flaggedIds || flagged})`,
      `decisions logged: ${total} total — ${blocked} blocked, ${flagged} flagged`,
      `decision log at: ${this.logPath} (metadata only, no message text)`,
    ].join("\n");
  }

  private get(senderId: string, now = Date.now()): SenderState {
    let s = this.state.get(senderId);
    if (!s) {
      s = { messageTimestamps: [], verdicts: [], threatScore: 0, firstSeenAt: now, lastSeenAt: now };
      this.state.set(senderId, s);
    }
    return s;
  }

  private hash(id: string): string {
    return crypto.createHash("sha256").update(id).digest("hex").slice(0, 16);
  }

  private appendLog(obj: unknown) {
    try {
      fs.appendFileSync(this.logPath, JSON.stringify(obj) + "\n");
    } catch { /* best-effort */ }
  }
}
