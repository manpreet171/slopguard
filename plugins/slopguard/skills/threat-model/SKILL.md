---
name: threat-model
description: Produce a short, concrete threat model before building a feature or app — assets, entry points, trust boundaries, and which parts a human must own. Use at the start of a project, before designing auth or payments, or when the user asks what could go wrong.
---

# Threat Model

Ten minutes here removes the class of bug that no scanner catches, because
missing authorization and absent rate limits are not patterns — they are
omissions, and you cannot grep for something that was never written.

Do this *before* the code exists. Retrofitting an authorization model onto a
finished app is a rewrite.

## Ask, briefly

You need four answers. Get them in one round of questions, not an interrogation:

1. **What is this and who uses it?** Single-user tool, multi-tenant SaaS, public
   site with accounts, internal dashboard? Multi-tenancy is the fork in the road —
   it means every query needs a tenant scope.
2. **What data does it hold?** Anything personal, financial, health, or
   credential-shaped? Anything that would be a bad headline?
3. **What is the stack?** Specifically the database and auth: Supabase, Firebase,
   Clerk, Auth0, NextAuth, custom. This determines where authorization actually
   lives.
4. **Who can reach it?** Public internet, or behind a VPN or SSO?

If the user does not know yet, propose the safest default and move on.

## Then produce this — one page, no boilerplate

**Assets.** What an attacker wants, ranked. Usually: user records, session tokens,
the API keys in your env, the ability to send mail from your domain, and your
metered API spend. Name the actual tables and services, not categories.

**Entry points.** Every way data gets in: routes, forms, webhooks, uploads,
third-party callbacks, and the database itself if it is directly reachable from
the browser (Supabase and Firebase both are — this is the part people miss).

**Trust boundaries.** Draw the line where data stops being trusted. Browser →
server is one. Server → database is another. Your app → any third-party API is a
third, and responses crossing back are untrusted input too.

**Adversaries, concretely.** Not "hackers." A logged-in customer trying to read
another customer's row. A bot spraying credentials at your login. Someone who
found your repo and is reading the JS bundle for keys. An attacker who registered
a package name your assistant might hallucinate.

**Per-feature risk call.** For each planned feature, decide now:

| Risk | Who writes it | Examples |
|---|---|---|
| **Human-owned** | A person writes or line-by-line reviews it | Auth flows, session handling, payments, permission model, RLS policies, IAM, CI/CD, anything touching money or PII |
| **Reviewed generation** | AI drafts, human reviews against SG rules | API routes, data access, file uploads, webhook handlers, admin tooling |
| **Free generation** | Ship it, guards catch the rest | UI, styling, static content, pure presentation, tests |

Be explicit that the first row is not optional. Georgia Tech's Vibe Security Radar
traced 74 CVEs directly to AI-tool commits in early 2026 — the failures cluster
exactly here, in code the model wrote confidently and nobody read.

**Non-negotiables for this project.** Pick the five to eight SG rules that matter
most given the answers above, and state them as commitments. For a multi-tenant
Supabase app that is SG-6 (RLS on every table, service_role never in the client),
SG-7 (object-level checks), SG-1, SG-12, SG-17.

**What you are accepting.** Every project accepts risk. Name it — no audit
logging, no MFA, no rate limit on search, secrets in a `.env` on one laptop — so
it is a decision rather than a discovery.

## Write it down

Offer to save it as `docs/THREAT-MODEL.md` and to append the non-negotiables to
the project's `AGENTS.md`, so the rules are in context for every future session
rather than living only in this conversation.

Keep it to one page. A threat model nobody rereads is decoration.
