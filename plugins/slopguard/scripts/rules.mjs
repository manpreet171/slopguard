/**
 * SLOPGUARD — detection rule library
 *
 * Each rule maps to a numbered clause in AGENTS.md so that a block message
 * can cite the rule the agent violated. The agent then reads the rule and
 * self-corrects instead of guessing at what upset the linter.
 *
 * severity: "deny" halts the write. "ask" surfaces a prompt to the human.
 * Keep "deny" for patterns that are unambiguous. Heuristics get "ask" —
 * a guard that cries wolf gets uninstalled, and an uninstalled guard
 * defends nothing.
 */

/** Files where a leaked server-side key becomes a public key. */
export const CLIENT_SIDE_HINTS = [
  // `app/` is deliberately absent: it is the *server* directory in Rails,
  // Laravel and Django, so treating it as a client bundle flagged server code
  // that is doing exactly the right thing.
  /(^|[\\/])(src|pages|components|public|static|assets|www|client|frontend)[\\/]/i,
  /\.(jsx|tsx|vue|svelte|astro)$/i,
];

/** Paths that legitimately contain secret-shaped strings. */
export const ALLOWLIST_PATHS = [
  /(^|[\\/])\.env\.example$/i,
  /(^|[\\/])(node_modules|vendor|dist|build|\.next|\.nuxt|target|__pycache__)[\\/]/i,
  /(^|[\\/])(test|tests|spec|__tests__|fixtures|mocks|examples?)[\\/]/i,
  /\.(lock|min\.js|map|snap)$/i,
  /(^|[\\/])(package-lock\.json|yarn\.lock|pnpm-lock\.yaml)$/i,
  // Slopguard's own rule library is made of these patterns by definition.
  /(^|[\\/])slopguard[\\/]/i,
  /(^|[\\/])(AGENTS|CLAUDE|THREATS|README)\.md$/i,
];

/** Literal values that are obviously not real credentials. */
const PLACEHOLDER = /^(x{3,}|y{3,}|\.{3}|<[^>]*>|\{\{.*\}\}|\$\{.*\}|changeme|placeholder|your[-_ ]?\w*|example|dummy|test|fake|todo|redacted|null|none|abc123|foo|bar)$/i;

function isPlaceholder(value) {
  if (!value) return true;
  const v = value.trim();
  if (v.length < 8) return true;
  if (PLACEHOLDER.test(v)) return true;
  if (/^(sk|pk)[-_](test|example|xxx)/i.test(v)) return true;
  // Reading from somewhere else is the correct pattern, not a finding.
  if (/process\.env|os\.environ|getenv|import\.meta\.env|Deno\.env|secrets\./i.test(v)) return true;
  return false;
}

/**
 * High-confidence credential formats. These are issuer-defined shapes —
 * a match is a real key, not a guess.
 */
export const SECRET_PATTERNS = [
  { id: 'SG-1', name: 'AWS access key ID', re: /\bAKIA[0-9A-Z]{16}\b/ },
  { id: 'SG-1', name: 'AWS secret access key', re: /aws_?secret_?access_?key\s*[=:]\s*["']([A-Za-z0-9/+=]{40})["']/i, group: 1 },
  { id: 'SG-1', name: 'GitHub personal access token', re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/ },
  { id: 'SG-1', name: 'GitHub fine-grained token', re: /\bgithub_pat_[A-Za-z0-9_]{60,}\b/ },
  { id: 'SG-1', name: 'Stripe live secret key', re: /\bsk_live_[A-Za-z0-9]{16,}\b/ },
  { id: 'SG-1', name: 'Stripe restricted key', re: /\brk_live_[A-Za-z0-9]{16,}\b/ },
  // No interior hyphens. Real keys have none; long kebab-case identifiers like
  // `sk-loading-placeholder-animation-container` do, and were a hard DENY.
  { id: 'SG-1', name: 'OpenAI API key', re: /\bsk-(proj-)?[A-Za-z0-9_]{32,}\b/ },
  { id: 'SG-1', name: 'Anthropic API key', re: /\bsk-ant-[A-Za-z0-9_-]{32,}\b/ },
  { id: 'SG-1', name: 'Google API key', re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { id: 'SG-1', name: 'Slack token', re: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/ },
  { id: 'SG-1', name: 'Slack webhook', re: /https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9_/-]{20,}/ },
  { id: 'SG-1', name: 'SendGrid API key', re: /\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b/ },
  { id: 'SG-1', name: 'Twilio account SID', re: /\bAC[a-f0-9]{32}\b/ },
  { id: 'SG-1', name: 'private key block', re: /-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/ },
  { id: 'SG-1', name: 'database connection string with inline password', re: /\b(postgres|postgresql|mysql|mongodb(\+srv)?|redis|amqp):\/\/[^\s:@'"]+:[^\s:@'"]{6,}@[^\s'"]+/ },
];

/**
 * Supabase / Firebase service keys shipped to the browser. This is the
 * single most common catastrophic mistake in the Lovable/Bolt/Base44 class
 * of vibe-coded app: the service_role key bypasses every RLS policy, so
 * publishing it hands any visitor full read/write on the entire database.
 */
export const CLIENT_SECRET_PATTERNS = [
  {
    id: 'SG-6',
    name: 'Supabase service_role key in client-reachable code',
    // service_role JWTs carry the role in the payload; match the claim.
    re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]*(c2VydmljZV9yb2xl|InNlcnZpY2Vfcm9sZSI)[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+/,
  },
  // Requires an assignment. A comment warning people NOT to put the key here
  // used to be a hard DENY, which is the fastest way to get uninstalled.
  { id: 'SG-6', name: 'SUPABASE_SERVICE_ROLE_KEY referenced in client bundle', re: /SUPABASE_SERVICE_ROLE(_KEY)?\s*[=:]\s*["'`]/ },
  { id: 'SG-6', name: 'service_role client construction', re: /createClient\s*\([^)]*service_?role/i },
];

/** Code-shape rules. `deny` = provably unsafe. `ask` = needs a human eye. */
export const CODE_PATTERNS = [
  {
    id: 'SG-2',
    severity: 'deny',
    name: 'SQL built by string interpolation',
    langs: /\.(js|jsx|ts|tsx|mjs|cjs|py|rb|php|go|java|cs)$/i,
    re: /\b(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b[^;'"`]{0,200}?(\$\{[^}]+\}|"\s*\+\s*\w|'\s*\+\s*\w|%s['"]?\s*%|\bf["'][^"']*\{)/is,
    fix: 'Use a parameterized query / prepared statement. Pass values as bound arguments, never concatenate them into the SQL string.',
  },
  {
    id: 'SG-2',
    severity: 'deny',
    name: 'SQL built inside a Python f-string',
    langs: /\.py$/i,
    // The f-prefix precedes the SQL keyword, so this needs its own pattern
    // rather than an alternation on the generic interpolation rule.
    re: /\bf["'][^"']*\b(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b[^"']*\{[^}]+\}/is,
    fix: 'Use cur.execute("… WHERE n = %s", (name,)) and let the driver bind the value. An f-string interpolates before the driver ever sees it.',
  },
  {
    id: 'SG-3',
    severity: 'deny',
    name: 'shell command built from a variable',
    re: /\b(child_process\.)?(exec|execSync|spawnSync)\s*\(\s*[`"'][^`"']*(\$\{|"\s*\+|'\s*\+)/,
    fix: 'Use execFile/spawn with an argument array so the shell never parses user input. If you must build a string, allowlist the input against a fixed set.',
  },
  {
    id: 'SG-3',
    severity: 'deny',
    name: 'Python shell call with interpolated input',
    langs: /\.py$/i,
    re: /\b(os\.system|os\.popen|subprocess\.(run|call|Popen|check_output))\s*\(\s*(f["']|["'][^"']*["']\s*[+%]|\w+\s*\+)/,
    fix: 'Pass a list of arguments and leave shell=False. Never build the command as a string from request data.',
  },
  {
    id: 'SG-3',
    severity: 'deny',
    name: 'eval / exec on dynamic input',
    re: /\b(eval|exec)\s*\(\s*(?!["'`][^"'`]*["'`]\s*\))[\w.[\]]*(req|request|input|params|query|body|argv|user|data)\b/i,
    fix: 'There is almost always a parser, a lookup table, or a switch that does this safely. Remove the eval.',
  },
  {
    id: 'SG-9',
    severity: 'deny',
    name: 'unsafe deserialization',
    re: /\b(pickle\.loads?|cPickle\.loads?|yaml\.load\s*\((?![^)]*Safe)|marshal\.loads|Marshal\.load|unserialize\s*\()/,
    fix: 'Use JSON, or yaml.safe_load. Deserializing an untrusted blob into live objects is remote code execution by design.',
  },
  {
    id: 'SG-18',
    severity: 'deny',
    name: 'TLS certificate verification disabled',
    re: /(verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0|InsecureSkipVerify\s*:\s*true|CURLOPT_SSL_VERIFYPEER\s*,\s*(false|0))/,
    fix: 'Fix the certificate chain instead. Disabling verification turns TLS into plaintext with extra steps.',
  },
  {
    id: 'SG-8',
    severity: 'deny',
    name: 'Math.random() used for a security value',
    re: /\b(token|secret|nonce|salt|otp|code|key|password|session[_a-z]*id|reset)\w*\s*[=:][^;\n]{0,80}Math\.random\s*\(/i,
    fix: 'Use crypto.randomUUID() or crypto.randomBytes(). Math.random() is predictable and is not a security primitive.',
  },
  {
    id: 'SG-8',
    severity: 'deny',
    name: 'password hashed with a fast digest',
    re: /\b(createHash\s*\(\s*["'](md5|sha1|sha256)["']|hashlib\.(md5|sha1|sha256)\s*\()[^;\n]{0,120}\b(password|passwd|pwd)\b/i,
    fix: 'Use bcrypt, scrypt, or argon2id. Fast hashes are built to be fast, which is exactly what an offline cracker wants.',
  },
  {
    id: 'SG-8',
    severity: 'ask',
    name: 'deprecated / broken cipher construction',
    re: /\b(createCipher\s*\(|createDecipher\s*\(|DES|RC4|MODE_ECB|AES\.MODE_ECB)\b/,
    fix: 'Use createCipheriv with AES-256-GCM and a random IV. ECB leaks plaintext structure; createCipher derives a key with no salt.',
  },
  {
    id: 'SG-5',
    severity: 'ask',
    name: 'session cookie set without security flags',
    re: /\.cookie\s*\(\s*["'][^"']*(session|sess|auth|token|jwt|sid)[^"']*["']\s*,(?![^)]*httpOnly)/i,
    fix: 'Set { httpOnly: true, secure: true, sameSite: "strict" }. Without httpOnly, one XSS is a full account takeover.',
  },
  {
    id: 'SG-10',
    severity: 'deny',
    name: 'CORS wildcard combined with credentials',
    re: /(origin\s*:\s*["']\*["'][^}]{0,200}credentials\s*:\s*true|credentials\s*:\s*true[^}]{0,200}origin\s*:\s*["']\*["'])/is,
    fix: 'Reflect an explicit allowlist of origins. Wildcard + credentials lets any site on the internet make authenticated calls as your user.',
  },
  {
    id: 'SG-10',
    severity: 'deny',
    name: 'JWT decoded without verification',
    re: /(jwt\.decode\s*\((?![^)]*verify)|algorithms\s*:\s*\[\s*["']none["']|verify_signature["']?\s*:\s*False|jwt\.verify\s*\([^)]*,\s*null)/i,
    fix: 'Use jwt.verify with an explicit algorithm allowlist. jwt.decode reads attacker-controlled claims and trusts them.',
  },
  {
    id: 'SG-15',
    severity: 'ask',
    name: 'filesystem path built from request data',
    re: /\b(readFile|readFileSync|writeFile|writeFileSync|createReadStream|sendFile|open|unlink)\s*\(\s*[^)]{0,60}(req\.|request\.|params\.|query\.|body\.|args\.)/,
    fix: 'Resolve the path and assert it stays inside the intended root, or index by an opaque ID instead of a caller-supplied name.',
  },
  {
    id: 'SG-11',
    severity: 'ask',
    name: 'outbound request to a caller-supplied URL (SSRF)',
    re: /\b(fetch|axios(\.(get|post|put|delete))?|requests\.(get|post)|urlopen|http\.get)\s*\(\s*[^)]{0,40}(req\.|request\.|params\.|query\.|body\.)/,
    fix: 'Allowlist the destination host. An unrestricted fetch reaches your cloud metadata endpoint and internal services.',
  },
  {
    id: 'SG-4',
    severity: 'ask',
    name: 'React dangerouslySetInnerHTML',
    re: /dangerouslySetInnerHTML|\.innerHTML\s*=\s*[^;'"]*(\$\{|\+\s*\w)/,
    fix: 'Render as text, or sanitize with DOMPurify first. This is the standard stored-XSS path.',
  },
];

/**
 * Characters with no business in a text file that an AI agent reads as
 * instructions. Pillar Security's "Rules File Backdoor" hides directives
 * from human review inside these while the model still obeys them.
 */
export const INVISIBLE_CHARS = [
  { cp: 0x200b, name: 'ZERO WIDTH SPACE' },
  { cp: 0x200c, name: 'ZERO WIDTH NON-JOINER' },
  { cp: 0x200d, name: 'ZERO WIDTH JOINER' },
  { cp: 0x2060, name: 'WORD JOINER' },
  { cp: 0xfeff, name: 'ZERO WIDTH NO-BREAK SPACE' },
  { cp: 0x00ad, name: 'SOFT HYPHEN' },
  { cp: 0x202a, name: 'LEFT-TO-RIGHT EMBEDDING' },
  { cp: 0x202b, name: 'RIGHT-TO-LEFT EMBEDDING' },
  { cp: 0x202c, name: 'POP DIRECTIONAL FORMATTING' },
  { cp: 0x202d, name: 'LEFT-TO-RIGHT OVERRIDE' },
  { cp: 0x202e, name: 'RIGHT-TO-LEFT OVERRIDE' },
  { cp: 0x2066, name: 'LEFT-TO-RIGHT ISOLATE' },
  { cp: 0x2067, name: 'RIGHT-TO-LEFT ISOLATE' },
  { cp: 0x2068, name: 'FIRST STRONG ISOLATE' },
  { cp: 0x2069, name: 'POP DIRECTIONAL ISOLATE' },
];

const INVISIBLE_RE = new RegExp(
  `[${INVISIBLE_CHARS.map((c) => `\\u{${c.cp.toString(16)}}`).join('')}]|[\\u{E0000}-\\u{E007F}]`,
  'u',
);

export function findInvisible(text) {
  const hits = [];
  // A leading U+FEFF is a UTF-8 byte order mark, which every Windows editor
  // writes. Flagging it would bury real findings under noise.
  const lines = text.replace(/^﻿/, '').split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    if (!INVISIBLE_RE.test(lines[i])) continue;
    const found = new Set();
    for (const ch of lines[i]) {
      const cp = ch.codePointAt(0);
      if (cp >= 0xe0000 && cp <= 0xe007f) found.add('UNICODE TAG (invisible)');
      const known = INVISIBLE_CHARS.find((c) => c.cp === cp);
      if (known) found.add(known.name);
    }
    hits.push({ line: i + 1, chars: [...found] });
  }
  return hits;
}

export function isAllowlisted(filePath) {
  const p = filePath || '';
  return ALLOWLIST_PATHS.some((re) => re.test(p));
}

export function looksClientSide(filePath) {
  const p = filePath || '';
  return CLIENT_SIDE_HINTS.some((re) => re.test(p));
}

/** Scan a blob of about-to-be-written code. Returns findings, worst first. */
export function scanContent(content, filePath) {
  const findings = [];
  if (!content) return findings;

  for (const p of SECRET_PATTERNS) {
    const m = content.match(p.re);
    if (!m) continue;
    const value = p.group ? m[p.group] : m[0];
    if (isPlaceholder(value)) continue;
    findings.push({
      id: p.id,
      severity: 'deny',
      name: p.name,
      evidence: redact(value),
      fix: 'Move this to an environment variable or a secret manager, reference it via process.env / os.environ, and rotate the exposed credential — assume it is already public.',
    });
  }

  if (looksClientSide(filePath)) {
    for (const p of CLIENT_SECRET_PATTERNS) {
      const m = content.match(p.re);
      if (!m) continue;
      findings.push({
        id: p.id,
        severity: 'deny',
        name: p.name,
        evidence: redact(m[0]),
        fix: 'This file ships to the browser. A service_role key there bypasses every Row Level Security policy you wrote — any visitor gets full database access. Use the anon/publishable key on the client and keep privileged calls behind a server route or Edge Function.',
      });
    }
  }

  for (const p of CODE_PATTERNS) {
    if (p.langs && filePath && !p.langs.test(filePath)) continue;
    const m = content.match(p.re);
    if (!m) continue;
    findings.push({
      id: p.id,
      severity: p.severity,
      name: p.name,
      evidence: redact(m[0].slice(0, 160)),
      fix: p.fix,
    });
  }

  return findings.sort((a, b) => (a.severity === 'deny' ? -1 : 1) - (b.severity === 'deny' ? -1 : 1));
}

/** Never echo a live credential back into the transcript. */
export function redact(s) {
  if (!s) return '';
  const t = String(s).replace(/\s+/g, ' ').trim();
  if (t.length <= 24) return t;
  return `${t.slice(0, 12)}…${t.slice(-4)}`;
}
