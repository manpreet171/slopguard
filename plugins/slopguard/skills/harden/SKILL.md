---
name: harden
description: Audit code against the SG-1..SG-18 security rules and fix what it finds. Use when the user asks to harden, secure, or security-review code, when a Slopguard hook has blocked a write, or before shipping a feature that touches auth, payments, user data, or file uploads.
---

# Harden

Find real vulnerabilities in this codebase and fix them. Not a checklist recital —
a working audit that ends with the code actually changed.

## Scope it first

Ask the user what to audit if it is ambiguous. Default to the current diff
(`git diff` / `git diff --staged`) when there is one, otherwise the files most
recently touched. Auditing an entire mature repo in one pass produces a wall of
noise nobody acts on; go feature by feature.

## Read the rules

Read `AGENTS.md` in the project root for the full SG-1..SG-18 text. If it is not
there, read the copy at `${CLAUDE_PLUGIN_ROOT}/../../AGENTS.md`. Cite rule IDs in
every finding so the user can look up the reasoning.

## Trace, don't grep

Pattern matching finds the easy half. The expensive bugs are structural, so work
from the entry points inward:

1. **Enumerate every entry point.** Routes, API handlers, form actions, webhook
   receivers, server actions, edge functions, message consumers, cron jobs.
2. **For each one, follow the data.** Where does input arrive, what validates it
   (SG-17), where does it reach a query, a shell, a filesystem path, an outbound
   request, or an HTML render?
3. **For each one, ask the authorization question twice.** Is the caller
   authenticated, *and* does the code verify this caller owns this specific
   object? Missing object-level checks (IDOR) is the most common serious flaw in
   AI-generated CRUD and it is invisible to grep — the code looks complete
   because it does have an auth check, just the wrong one. (SG-7)
4. **Check the data layer independently.** For Supabase: is RLS enabled on every
   table, with real policies? For Firebase: are rules default-deny? A perfect API
   layer is irrelevant if the database is directly reachable with the anon key.
   (SG-6)
5. **Check what is missing, not just what is wrong.** No rate limit on login. No
   CSRF protection. No lockout. Absent controls do not appear in a diff.

## Then sweep for the mechanical ones

Secrets in source and history (SG-1). String-built queries (SG-2). Shell and eval
on request data (SG-3). Unverified or unpinned dependencies (SG-4). Cookie flags
(SG-5). Weak hashes and `Math.random` for tokens (SG-8). Unsafe deserialization
(SG-9). CORS and JWT handling (SG-10). Disabled TLS verification (SG-18).

## Report like this

Group by severity, worst first. For each finding:

```
[SG-7] Object-level authorization missing — src/api/orders/[id].ts:14
  What: Handler checks for a valid session but fetches the order by ID without
        scoping to the caller. Any logged-in user can read any order.
  Proof: GET /api/orders/1042 with any valid session returns order 1042.
  Fix:   Scope the query — .eq('user_id', session.user.id) — so a mismatched
         ID returns nothing rather than someone else's data.
```

Every finding needs a concrete exploit path. "This could be unsafe" is not a
finding; "an authenticated user changes the ID in the URL and reads another
customer's address" is. If you cannot describe how it is exploited, mark it as a
hardening suggestion rather than a vulnerability, and say so.

**Never invent a finding to look thorough.** A short honest report builds trust
that a long padded one destroys. If the code is clean, say it is clean and say
what you checked.

## Fix

Offer to fix. Then fix the confirmed findings, starting with the highest severity,
and follow the SG rules in the fix itself — it is embarrassingly easy to introduce
SG-2 while fixing SG-7.

Where the fix is a design decision (which auth model, how strict a CORS policy,
whether to add a dependency), present the options and let the user choose. That is
PD-4, and it applies to you.

## Close honestly

State what you did not cover: dependency CVEs if you did not run a scanner, git
history if you did not search it, infrastructure and IAM, runtime behavior, and
anything the user scoped out. An audit that implies more coverage than it had is
worse than no audit, because it manufactures confidence.
