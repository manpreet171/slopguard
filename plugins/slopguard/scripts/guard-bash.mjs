#!/usr/bin/env node
/**
 * SLOPGUARD / guard-bash
 * PreToolUse on Bash.
 *
 * Two jobs:
 *
 * 1. Slopsquatting interception. Spracklen et al. (USENIX Security 2025)
 *    generated 576,000 code samples across 16 models and found 19.7% of
 *    recommended packages did not exist — 205,474 unique hallucinated names,
 *    43% of which reappeared on every re-run of the same prompt. That
 *    repeatability is the whole attack: an adversary mines a model for names
 *    it reliably invents, registers them, and waits for someone to run the
 *    install command their assistant just wrote.
 *
 *    So: before any install executes, ask the registry whether each package
 *    is real, and how old it is. A name the model produced that does not
 *    exist is a hallucination. A name that exists but was published last
 *    week, matching a hallucination the model just emitted, is bait.
 *
 * 2. Refuse to pipe the internet into a shell.
 *
 * Fails open on network trouble. A guard that blocks your work when the
 * wifi drops is a guard you will disable.
 */

import { readHookInput, allow, decide, failOpen } from './io.mjs';

const FETCH_TIMEOUT_MS = 4000;
const MAX_PACKAGES = 12;
const YOUNG_PACKAGE_DAYS = 120;

const SHELL_PATTERNS = [
  {
    id: 'SG-16',
    re: /\b(curl|wget)\b[^|;&]*\|\s*(sudo\s+)?(ba|z|k)?sh\b/,
    name: 'remote script piped directly into a shell',
    fix: 'Download to a file, read it, then run it. `curl … | sh` executes whatever the server decides to return at that moment — including a different payload for your IP than the one you reviewed.',
  },
  {
    id: 'SG-16',
    re: /\bnpm\s+(install|i)\b[^|;&]*--ignore-scripts=false|\bnpm\s+config\s+set\s+ignore-scripts\s+false/,
    name: 'npm lifecycle scripts explicitly re-enabled',
    fix: 'Install scripts run arbitrary code at install time and are the primary payload delivery mechanism for malicious packages. Leave them off.',
  },
  {
    id: 'SG-1',
    // No \b before the group: a space followed by "." has no word boundary
    // between them, so anchoring on one silently never matches ".env".
    re: /\bgit\s+(commit|add)\b[^|;&]*(\.env|id_rsa|\.pem|credentials)\b/,
    name: 'credential file staged for commit',
    fix: 'Add it to .gitignore. Anything committed is in the history permanently, even after a later delete.',
  },
  {
    id: 'SG-14',
    re: /\bchmod\s+(-R\s+)?777\b/,
    name: 'world-writable permissions',
    fix: 'Grant the narrowest permission that works — usually 755 for directories, 644 for files.',
  },
];

/** Extract package names from an install command. */
function parseInstalls(cmd) {
  const out = [];
  // Split on shell separators so `cd x && npm i foo` is handled.
  for (const segment of cmd.split(/&&|\|\||;|\n/)) {
    const s = segment.trim();

    const npm = s.match(/\b(?:npm|pnpm|bun)\s+(?:install|i|add)\s+(.+)/);
    if (npm) out.push(...tokens(npm[1]).map((n) => ({ ecosystem: 'npm', name: n })));

    const yarn = s.match(/\byarn\s+add\s+(.+)/);
    if (yarn) out.push(...tokens(yarn[1]).map((n) => ({ ecosystem: 'npm', name: n })));

    const pip = s.match(/\b(?:pip3?|uv\s+pip|python3?\s+-m\s+pip)\s+install\s+(.+)/);
    if (pip) out.push(...tokens(pip[1]).map((n) => ({ ecosystem: 'pypi', name: n })));
  }
  return dedupe(out).slice(0, MAX_PACKAGES);
}

function tokens(rest) {
  return rest
    .split(/\s+/)
    .filter(Boolean)
    // Drop flags and their obvious values.
    .filter((t) => !t.startsWith('-'))
    // Local paths, VCS refs and tarballs are not registry lookups.
    .filter((t) => !/^(\.|\/|~|git\+|https?:|file:|git@)/.test(t))
    .filter((t) => !/\.(tgz|tar\.gz|whl|zip)$/.test(t))
    // `-r requirements.txt` leaves the filename behind.
    .filter((t) => !/\.(txt|toml|cfg)$/.test(t))
    .map(stripVersion)
    .filter((t) => /^[@a-zA-Z0-9._/-]+$/.test(t) && t.length > 0);
}

function stripVersion(token) {
  // Keep the leading @ of a scope, strip a trailing @version.
  const at = token.lastIndexOf('@');
  let name = at > 0 ? token.slice(0, at) : token;
  // pip: package>=1.2, package[extra]
  name = name.split(/[<>=!~[]/)[0];
  return name.trim();
}

function dedupe(list) {
  const seen = new Set();
  return list.filter((p) => {
    const k = `${p.ecosystem}:${p.name}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

async function getJson(url) {
  const res = await fetch(url, {
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    headers: { accept: 'application/json', 'user-agent': 'slopguard' },
  });
  if (res.status === 404) return { missing: true };
  if (!res.ok) return { unknown: true };
  return { data: await res.json() };
}

async function inspect(pkg) {
  try {
    if (pkg.ecosystem === 'npm') {
      const r = await getJson(`https://registry.npmjs.org/${encodeURIComponent(pkg.name).replace('%40', '@')}`);
      if (r.missing) return { ...pkg, verdict: 'nonexistent' };
      if (r.unknown || !r.data) return { ...pkg, verdict: 'unknown' };
      const created = r.data.time?.created;
      return { ...pkg, verdict: 'exists', created, ageDays: ageDays(created) };
    }
    const r = await getJson(`https://pypi.org/pypi/${encodeURIComponent(pkg.name)}/json`);
    if (r.missing) return { ...pkg, verdict: 'nonexistent' };
    if (r.unknown || !r.data) return { ...pkg, verdict: 'unknown' };
    const dates = Object.values(r.data.releases || {})
      .flat()
      .map((f) => f?.upload_time_iso_8601)
      .filter(Boolean)
      .sort();
    const created = dates[0];
    return { ...pkg, verdict: 'exists', created, ageDays: ageDays(created) };
  } catch {
    return { ...pkg, verdict: 'unknown' };
  }
}

function ageDays(iso) {
  if (!iso) return null;
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return null;
  return Math.floor((Date.now() - t) / 86400000);
}

try {
  const input = await readHookInput();
  const cmd = input.tool_input?.command || '';
  if (!cmd.trim()) allow();

  for (const p of SHELL_PATTERNS) {
    if (!p.re.test(cmd)) continue;
    decide(
      'deny',
      [
        `SLOPGUARD blocked this command — [${p.id}] ${p.name}.`,
        '',
        `fix: ${p.fix}`,
        '',
        'Rule text lives in AGENTS.md.',
      ].join('\n'),
    );
  }

  const packages = parseInstalls(cmd);
  if (!packages.length) allow();

  const results = await Promise.all(packages.map(inspect));

  const ghosts = results.filter((r) => r.verdict === 'nonexistent');
  const young = results.filter((r) => r.verdict === 'exists' && r.ageDays !== null && r.ageDays < YOUNG_PACKAGE_DAYS);

  if (ghosts.length) {
    decide(
      'deny',
      [
        `SLOPGUARD blocked this install — [SG-4] ${ghosts.length} package(s) do not exist in the registry:`,
        '',
        ...ghosts.map((g) => `  • ${g.name}  (${g.ecosystem}: 404 not found)`),
        '',
        'This is the signature of a package hallucination. The model invented a plausible name.',
        'Do NOT retry the install and do NOT try a similar-looking name — near-misses of hallucinated',
        'names are exactly what slopsquatters register.',
        '',
        'fix: Search for the real library that provides this functionality, confirm its name on the',
        'registry or its official docs, and import that. If no such library exists, write the code',
        'directly or pick a different approach.',
      ].join('\n'),
    );
  }

  if (young.length) {
    decide(
      'ask',
      [
        `SLOPGUARD flagged ${young.length} newly-published package(s) — [SG-4]:`,
        '',
        ...young.map((y) => `  • ${y.name}  (${y.ecosystem}: first published ${y.ageDays} days ago)`),
        '',
        'The package exists, but it is young. A registry entry created recently and matching a name',
        'an AI suggested is the exact shape of a slopsquatting payload: the attacker mines models for',
        'names they reliably hallucinate, then registers them.',
        '',
        'Before approving, confirm: is this the library you actually meant? Does it have a real',
        'repository, real maintainers, and a history that predates your prompt? A legitimately new',
        'package is fine — an unfamiliar one that appeared right when you needed it is not.',
      ].join('\n'),
    );
  }

  allow();
} catch (err) {
  failOpen(err);
}
