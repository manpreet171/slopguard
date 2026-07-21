---
name: preflight
description: Last-check before deploying or making a repo public — secrets in git history, exposed database policies, debug flags, dependency CVEs, and client bundle leaks. Use when the user is about to deploy, ship, launch, go live, or publish a repository.
---

# Preflight

The checks that only matter once, right before real users and real attackers can
reach the thing. Run this when the user says deploy, ship, launch, go live, or
"make the repo public."

Work through all six sections. Report findings as a go / no-go, and be willing to
say no-go.

## 1. Secrets — including history

A `.env` in `.gitignore` today does not help if it was committed last month.
History is the whole risk surface.

```bash
git log --all --full-history --diff-filter=A --name-only -- '*.env*' '*.pem' '*id_rsa*' '*credentials*'
git log -p --all -S 'sk_live' -S 'AKIA' -S 'BEGIN PRIVATE KEY' --oneline
```

Check the working tree too, then check what actually ships: `.env.local`,
`.env.production`, CI workflow files, Dockerfiles, and anything in the client
bundle (see §3).

**Anything found is burned.** Rotate it. Removing the file or rewriting history
does not un-publish a key that was pushed — assume it was scraped within minutes,
because public repos are scraped continuously.

## 2. The data layer is the perimeter

For Supabase, Firebase, and anything else the browser talks to directly, the
database *is* the API. Verify, do not assume:

- **RLS enabled on every table**, with policies that actually restrict rows —
  a policy of `USING (true)` is RLS theatre.
- **`service_role` / admin keys are not in any client-reachable file.** Grep the
  built bundle, not just the source.
- Storage buckets: are they public? Should they be?
- Database advisors / security linter output, if the platform has one.
- Default-deny rules for Firebase.

This is where vibe-coded apps actually get breached. Escape.tech scanned 5,600
production apps built on Lovable, Base44, Bolt and similar, and found 2,000+
vulnerabilities, 400+ exposed secrets, and 175 instances of exposed PII — in live
apps serving real users, not in test projects.

## 3. What the browser can actually see

Build the app, then read the output:

```bash
npm run build
grep -rEn "sk_live|AKIA|service_role|SUPABASE_SERVICE|BEGIN PRIVATE KEY|xox[baprs]-" dist/ build/ .next/static/ 2>/dev/null
```

Any env var not prefixed `NEXT_PUBLIC_` / `VITE_` / `PUBLIC_` should be absent.
If it is present, the prefix rule was bypassed somewhere.

Also check: source maps disabled in production, no `.git` directory served, no
`/admin` route reachable without auth, and no debug/test endpoints left in.

## 4. Dependencies

```bash
npm audit --omit=dev        # or: pnpm audit / yarn npm audit
pip-audit                   # or: safety check
```

Confirm the lockfile is committed. Then scan the dependency list for anything the
team does not recognize — packages added by an assistant that nobody vetted are
the slopsquatting exposure (SG-4). For any unfamiliar name: does it have a real
repository, real maintainers, and a publish history that predates the feature it
was added for?

## 5. Runtime posture

- Debug mode off. Stack traces not returned to clients (SG-13).
- Rate limits live on login, signup, password reset, and any endpoint that sends
  mail or calls a paid API (SG-12).
- Security headers: HSTS, `X-Content-Type-Options`, a real CSP, frame-ancestors.
- HTTPS enforced with redirect. TLS verification on everywhere (SG-18).
- CORS is an explicit allowlist, never `*` with credentials (SG-10).
- Backups exist and someone has restored one at least once.
- Logging captures auth events and excludes secrets and PII (SG-14).

## 6. Agent supply chain

Before making a repo public, or after pulling from a shared branch:

- Are `.mcp.json`, `.cursor/mcp.json`, `.claude/settings.json`, and hook configs
  exactly what you expect? A changed entry you did not change is the MCPoison
  pattern (SG-16).
- Do `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, or `.cursor/rules` contain hidden
  Unicode or instruction-shaped text? Slopguard's session hook checks this
  automatically — confirm it ran clean.
- Publishing these files publishes your agent's instructions. Read them once as
  an outsider would.

## Verdict

```
PREFLIGHT — <project>

BLOCKING (n)      must fix before deploy
SHOULD FIX (n)    fix this week
ACCEPTED (n)      known and deliberate

NOT CHECKED       infrastructure, IAM, runtime behavior under load, <anything else>

VERDICT: NO-GO — <the single most important reason>
```

Be specific about what you did not check. A preflight that implies full coverage
is more dangerous than no preflight, because it converts an unknown risk into a
false sense of safety.
