// detect.ts — deterministic detection layers for jerith-guard.
//
// Five independent scorers over inbound text:
//   injection    — prompt-injection & agent-hijack patterns
//   spam         — spam/dilution patterns (burst handled server-side)
//   hacking      — exploitation attempts, shell/coding payloads
//   exfiltration — credential/config extraction attempts
//   impersonation— persona/identity sabotage & safety-strip attempts
//
// Every rule is a plain regex with a weight; a text hits a layer when its
// matched weight crosses the layer threshold. No ML, no network — the whole
// file is auditable in one sitting. Return shape: { score, matches } where
// matches are rule ids so logs never contain raw user text.

export interface LayerHit {
  score: number;
  matches: string[];
}

interface Rule {
  id: string;
  weight: number;
  re: RegExp;
}

const rx = (source: string, flags = "i") => new RegExp(source, flags);

// ── Prompt injection / agent hijack ────────────────────────────────────────
const INJECTION_RULES: Rule[] = [
  { id: "inj.ignore-previous", weight: 3, re: rx("\\bignore (all |any |your |the )?(previous|prior|above|earlier) (instructions|prompts?|rules?|directives?|messages?)\\b") },
  { id: "inj.disregard",        weight: 3, re: rx("\\b(disregard|forget|override|discard) (all |your |the |any )?(system|previous|prior|above|initial|original) (prompt|instructions?|rules?|messages?|directives?)\\b") },
  { id: "inj.new-instructions", weight: 2, re: rx("\\b(new|updated|revised) (instructions?|directives?|rules?)\\s*[:：]") },
  { id: "inj.system-prompt",    weight: 3, re: rx("\\b(your|the) (real |actual |true )?system prompt\\b") },
  { id: "inj.reveal-prompt",    weight: 3, re: rx("\\b(repeat|reveal|print|show|output|copy|paste|leak) (your |the |your full |your entire )?(system prompt|instructions|initial prompt|hidden prompt)\\b") },
  { id: "inj.roleplay-override",weight: 1, re: rx("\\bfrom now on,? you (are|will be)\\b") },
  { id: "inj.developer-mode",   weight: 3, re: rx("\\b(developer|dan|jailbreak|god|admin) ?mode\\b") },
  { id: "inj.no-restrictions",  weight: 2, re: rx("\\b(without|no|ignore) (any )?(restrictions|guardrails|filters|safety|content policy|limitations)\\b") },
  { id: "inj.you-must-obey",    weight: 2, re: rx("\\byou (must|have to|need to) (obey|comply with|follow) (my|these|the) (instructions|commands)\\b") },
  { id: "inj.hidden-context",   weight: 2, re: rx("<<\\s*(system|assistant)|\\[\\s*system\\s*\\]|\\(\\s*system\\s*:\\s") },
  { id: "inj.fake-system-tag",  weight: 3, re: rx("(^|\\n)\\s*system\\s*:", "m") },
  { id: "inj.end-of-prompt",    weight: 2, re: rx("\\b(end of|above is) (the )?(system )?prompt\\b.{0,40}\\b(below|now|new)\\b", "is") },
  { id: "inj.act-as-unfiltered",weight: 2, re: rx("\\bact as (an? )?(unfiltered|uncensored|unrestricted)\\b") },
  { id: "inj.owner-impersonation", weight: 4, re: rx("\\bI am (the )?(owner|admin|administrator|your (creator|developer|operator))\\b.{0,80}\\b(grant|give|allow|unlock|bypass)\\b", "is") },
];

// ── Spam / dilution ───────────────────────────────────────────────────────
const SPAM_RULES: Rule[] = [
  { id: "spam.char-run",     weight: 2, re: rx("(.)\\1{25,}") },
  { id: "spam.word-repeat",  weight: 2, re: rx("\\b(\\w+)\\b[\\s\\S]{0,40}\\b\\1\\b[\\s\\S]{0,40}\\b\\1\\b[\\s\\S]{0,40}\\b\\1\\b[\\s\\S]{0,40}\\b\\1\\b[\\s\\S]{0,40}\\b\\1\\b") },
  { id: "spam.caps-shout",   weight: 1, re: rx("[A-Z0-9 !?$@#*]{60,}\\b") },
  { id: "spam.discord-inv",  weight: 1, re: rx("(discord\\.gg|discord\\.com/invite)/[\\w-]+") },
  { id: "spam.crypto-shill", weight: 2, re: rx("\\b(free (crypto|airdrop|nonce?gas)|double your (crypto|btc|eth|sol)|pump group|mint now|presale live)\\b") },
  { id: "spam.link-farm",    weight: 2, re: rx("(https?:\\/\\/\\S+\\s*){4,}", "") },
  { id: "spam.nonsense-dl",  weight: 1, re: rx("\\b\\w+\\b(?:.{1,20}?\\b\\w+\\b){30,}", "") },
];

// ── Hacking / exploitation ────────────────────────────────────────────────
const HACKING_RULES: Rule[] = [
  { id: "hack.pipe-curl",    weight: 4, re: rx("\\b(curl|wget)\\b[^|;&]{0,120}\\|\\s*(sudo )?(ba)?sh\\b") },
  { id: "hack.reverse-shell",weight: 4, re: rx("\\b(bash|sh|nc|ncat|netcat|socat)\\b[^\\n]{0,80}\\b(-e|-c)\\s*(/bin/(ba)?sh|cmd\\.exe|powershell)\\b") },
  { id: "hack.dev-tcp",      weight: 3, re: rx("\\b/dev/tcp/[\\d.]+/\\d+\\b") },
  { id: "hack.base64-exec",  weight: 3, re: rx("(echo|printf)\\s+[A-Za-z0-9+/=]{80,}\\s*\\|\\s*(base64\\s*-?d|openssl?\\s+enc)\\b.{0,40}\\|\n?.{0,20}\\b(sh|bash)\\b", "i") },
  { id: "hack.eval-inject",  weight: 2, re: rx("\\b(eval|exec|system|popen)\\s*\\(\\s*[\"']\\s*\\$|\\$\\{\\s*IFS\\s*\\}|\\b\\$(IFS|\\{IFS\\})\\b") },
  { id: "hack.path-traverse",weight: 2, re: rx("(\\.\\./){4,}\\w+") },
  { id: "hack.sudo-force",   weight: 2, re: rx("\\bsudo\\b.{0,60}\\b(rm\\s+-rf\\s+[/~]|mkfs|dd\\s+if=|chmod\\s+777\\s+/)\\b") },
  { id: "hack.rmrf-root",    weight: 4, re: rx("\\brm\\s+-rf\\s+(/|~|\\$HOME)\\s") },
  { id: "hack.ssh-key-theft",weight: 3, re: rx("\\b(cat|cp|base64)\\b.{0,30}~?/\\.ssh/(id_rsa|id_ed25519|authorized_keys|known_hosts)\\b") },
  { id: "hack.sqlmap-xss",   weight: 1, re: rx("\\b(sqlmap|--dbs|union select|<script>document\\.|javascript:)\\b") },
];

// ── Credential / secret exfiltration ─────────────────────────────────────
const EXFIL_RULES: Rule[] = [
  { id: "exfil.env-dump",    weight: 3, re: rx("\\b(cat|print|type|curl|post)\\b.{0,40}\\b(\\.env|openclaw\\.json|\\.api-keys|credentials?\\.json|\\.ssh|\\.pgpass|agent\\.env)\\b") },
  { id: "exfil.token-mention",weight: 2, re: rx("\\b(send|post|upload|exfiltrate|dm|message)\\b.{0,60}\\b(api[- ]?key|token|secret|password|credentials?)\\b", "i") },
  { id: "exfil.webhook-post",weight: 3, re: rx("\\bcurl\\b.{0,60}\\b(discord\\.com/api/webhooks|hooks\\.slack\\.com|webhook\\.site|requestbin|pipedream)\\b") },
  { id: "exfil.config-probe",weight: 2, re: rx("\\b(read|show|dump|cat)\\b.{0,40}\\b(litellm[-_]config|openclaw\\.json|master[_ ]key)\\b") },
];

// ── Identity / persona sabotage (agent corruption) ───────────────────────
const IMPERSONATION_RULES: Rule[] = [
  { id: "imp.install-skill",  weight: 3, re: rx("\\b(install|run|apply|exec)\\b.{0,50}\\b(\\.agents\\/skills|blockrawnlp|openc\\.ai|skills add|rawFAST|personality pack)\\b", "i") },
  { id: "imp.strip-soul",     weight: 3, re: rx("\\b(delete|overwrite|replace|modify|edit)\\b.{0,50}\\b(SOUL\\.md|IDENTITY\\.md|soul\\/|security-rules|trust-identity)\\b", "i") },
  { id: "imp.personality-reset",weight: 3, re: rx("\\byou (are now|will now) (a )?(raw|unfiltered|no[- ]?persona|anti[- ]?jerith|evil|implanted)\\b") },
  { id: "imp.disable-safety", weight: 3, re: rx("\\b(disable|remove|strip) (your )?(safety|security) (rules|filters|systems)\\b") },
  { id: "imp.moral-subvert",  weight: 2, re: rx("\\b(you are|you were) (never|not actually) (bound|constrained|limited)\\b") },
  { id: "imp.cak-respond",    weight: 1, re: rx("\\brepeat after me[\\s\\S]{0,20}(i am|nihil|reprogram|malware)\\b", "i") },
];

function runLayer(rules: Rule[], text: string, threshold: number): LayerHit {
  const matches: string[] = [];
  let score = 0;
  let window = text.length;
  // cap text per rule to bound regex work
  const slice = window > 8000 ? text.slice(0, 8000) + "\n…[truncated]" + text.slice(-2000) : text;
  for (const rule of rules) {
    try {
      if (rule.re.test(slice)) {
        matches.push(rule.id);
        score += rule.weight;
      }
    } catch {
      /* regex errors never block the pipeline */
    }
  }
  return { score, matches: score >= threshold ? matches : [] };
}

export interface AnalysisInput {
  text: string;
  /** channel metadata that raises/lowers suspicion */
  senderIsOwner: boolean;
  isFirstContact: boolean;
  /** count of recent messages from this sender (server-tracked) */
  senderRecentCount: number;
}

export interface LayerConfig {
  injectionThreshold: number;
  spamThreshold: number;
  hackingThreshold: number;
  exfilThreshold: number;
  impersonationThreshold: number;
}

export const DEFAULT_LAYER_CONFIG: LayerConfig = {
  injectionThreshold: 3,
  spamThreshold: 3,
  hackingThreshold: 3,
  exfilThreshold: 3,
  impersonationThreshold: 3,
};

export interface Analysis {
  layers: Record<"injection" | "spam" | "hacking" | "exfiltration" | "impersonation", LayerHit>;
  triggered: string[];
  action: "pass" | "flag" | "block";
}

export function analyze(
  input: AnalysisInput,
  cfg: LayerConfig = DEFAULT_LAYER_CONFIG
): Analysis {
  const text = String(input.text ?? "");
  const ownerDiscount = input.senderIsOwner ? 0.5 : 1;   // owner gets halved weights
  const firstContactBoost = input.isFirstContact ? 1.25 : 1;
  const burstBoost = input.senderRecentCount > 5 ? 1.2 : 1;
  const mult = input.senderIsOwner ? ownerDiscount : firstContactBoost * burstBoost;

  const layers = {
    injection: runLayer(INJECTION_RULES, text, Math.ceil(cfg.injectionThreshold / mult)),
    spam: runLayer(SPAM_RULES, text, Math.ceil(cfg.spamThreshold / (input.senderIsOwner ? 2 : 1))),
    hacking: runLayer(HACKING_RULES, text, Math.ceil(cfg.hackingThreshold / mult)),
    exfiltration: runLayer(EXFIL_RULES, text, Math.ceil(cfg.exfilThreshold / mult)),
    impersonation: runLayer(IMPERSONATION_RULES, text, Math.ceil(cfg.impersonationThreshold / mult)),
  };

  const triggered = Object.entries(layers).filter(([, hit]) => hit.matches.length > 0).map(([name]) => name);

  const hackingOrExfil = layers.hacking.matches.length > 0 || layers.exfiltration.matches.length > 0;
  const injectionOrImpersonation = layers.injection.matches.length > 0 || layers.impersonation.matches.length > 0;
  const spamOnly = layers.spam.matches.length > 0 && !injectionOrImpersonation && !hackingOrExfil;

  const action: Analysis["action"] =
    hackingOrExfil || (injectionOrImpersonation && !input.senderIsOwner) ? "block"
    : spamOnly ? "flag"
    : triggered.length > 0 && !input.senderIsOwner ? "flag"
    : "pass";

  return { layers, triggered, action };
}
