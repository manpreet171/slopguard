# The Evidence

Every claim Slopguard makes, with its source. If a number here is wrong, open an
issue — this file is meant to be checkable, and a security tool that ships
unverifiable statistics has no standing to lecture anyone about trust.

Claims that could not be independently verified were cut rather than hedged.

---

## AI-generated code fails security tests at a measurable rate

**45% of AI-generated code samples introduced an OWASP Top 10 vulnerability.**
Veracode tested over 100 large language models across Java, Python, C# and
JavaScript. Java was worst at a 72% failure rate; Python, C# and JavaScript ranged
from 38% to 45%. Models failed to defend against cross-site scripting in 86% of
cases and log injection in 88%.

The finding that matters most: **newer and larger models did not do better.** This
is not a capability gap that the next release closes. Generating code that runs and
generating code that resists attack are different objectives, and only one of them
is being optimized.

- [Veracode — 2025 GenAI Code Security Report](https://www.veracode.com/blog/genai-code-security-report/) ([PDF](https://www.veracode.com/wp-content/uploads/2025_GenAI_Code_Security_Report_Final.pdf))
- [Veracode — Spring 2026 update](https://www.veracode.com/blog/spring-2026-genai-code-security/): no improvement trend.

## Real vulnerabilities in production apps, not lab conditions

**5,600 vibe-coded applications scanned → 2,000+ vulnerabilities, 400+ exposed
secrets, 175 instances of exposed PII.** Escape.tech scanned live applications
built on Lovable, Base44, Bolt.new and Vibe Studio — production apps serving real
users. Only high-confidence, confirmable findings were counted, so this is a floor
rather than a ceiling.

- [Escape.tech — The State of Security of Vibe Coded Apps](https://escape.tech/state-of-security-of-vibe-coded-apps)
- [Escape.tech — methodology](https://escape.tech/blog/methodology-how-we-discovered-vulnerabilities-apps-built-with-vibe-coding/)

## CVEs traced to specific AI-tool commits

Georgia Tech researcher Hanqing Zhao's **Vibe Security Radar** correlates CVE.org,
NVD, the GitHub Advisory Database and OSV against git history to attribute
vulnerabilities to the tool that authored the commit.

**74 confirmed AI-attributed CVEs**, with a sharp curve through early 2026: 6 in
January, 15 in February, 35 in March. Because most AI-authored commits are not
labeled as such, the researchers estimate the true count at five to ten times the
confirmed figure — roughly 400–700 cases.

**Claude Code accounts for 27 of the 74.** That is the largest single share, and
it is the direct reason this project targets Claude Code first: the guardrails
belong where the code is actually being written.

- [Cloud Security Alliance — Vibe Coding's Security Debt: The AI-Generated CVE Surge](https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-generated-code-vulnerability-surge-2026/) (April 2026)

## Slopsquatting: hallucinated packages as a supply chain

The most exploitable habit in AI-assisted development, and the one Slopguard
intercepts at the shell.

Spracklen et al. generated **576,000 code samples across 16 models** and found
**19.7% of recommended packages did not exist** — **205,474 unique hallucinated
names**. The composition: 38% were conflations of two real libraries
(`express-mongoose`), 13% were typo variants, and 51% were pure fabrication.

The part that makes it an attack rather than an annoyance: **re-running identical
prompts ten times, 43% of hallucinated names reappeared every single time**, and
58% reappeared more than once. Hallucination is not random noise. It is stable and
therefore minable.

So the attack is trivial to operate: prompt a popular model with common coding
tasks, collect the names it reliably invents, register them on npm or PyPI with a
payload in the install script, and wait for someone's assistant to write
`npm install <that name>`. No typo required — the name comes from the tool the
developer trusts.

The term was coined by Seth Larson, Security Developer-in-Residence at the Python
Software Foundation, in April 2025.

- [Spracklen et al., USENIX Security 2025](https://www.usenix.org/conference/usenixsecurity25) — *We Have a Package for You! A Comprehensive Analysis of Package Hallucinations by Code Generating LLMs*
- [Cloud Security Alliance — Slopsquatting research note](https://labs.cloudsecurityalliance.org/research/csa-research-note-slopsquatting-ai-supply-chain-20260419-csa/)
- [Aikido — Slopsquatting attacks already happening](https://www.aikido.dev/blog/slopsquatting-ai-package-hallucination-attacks)

---

## The tooling itself is now the attack surface

These are shipped, patched, real incidents. Every one of them targets the
developer's environment rather than the deployed application — which means your
production security posture is irrelevant to whether they succeed.

### CVE-2025-54135 — "CurXecute" (CVSS 8.6)

Cursor below 1.3.9 wrote in-workspace files without approval. An attacker posted a
crafted message to a **public Slack channel**; when a developer asked Cursor to
summarize Slack messages through an MCP integration, the injected instructions got
Cursor to write `~/.cursor/mcp.json`. Cursor auto-started MCP servers on config
write, so the attacker's command executed immediately — remote code execution at
developer privilege, from a message in a chat room.

Found by Aim Labs. Disclosed 7 July 2025, fixed in 1.3.9: any change to an MCP
config, down to adding a space, now requires explicit approval.

- [Cato Networks / Aim Labs — CurXecute](https://www.catonetworks.com/blog/curxecute-rce/)
- [Tenable — FAQ on both Cursor CVEs](https://www.tenable.com/blog/faq-cve-2025-54135-cve-2025-54136-vulnerabilities-in-cursor-curxecute-mcpoison)

### CVE-2025-54136 — "MCPoison" (CVSS 7.2)

Cursor 1.2.4 and below bound trust to an MCP entry's **key name**, not to the
command behind it. Once a collaborator approved a harmless-looking entry, an
attacker with write access to a shared repository could swap the command for
anything — `calc.exe` in the demo — with no re-prompt and no warning. Persistent
execution, triggered every time a teammate opened the project.

Found by Check Point Research. Disclosed 16 July 2025, fixed in 1.3.

- [Check Point Research — MCPoison](https://research.checkpoint.com/2025/cursor-vulnerability-mcpoison/)
- [NVD — CVE-2025-54136](https://nvd.nist.gov/vuln/detail/CVE-2025-54136)

### The Rules File Backdoor

Pillar Security demonstrated that hidden Unicode — zero-width characters,
bidirectional overrides, Unicode tag characters — embedded in the rule files that
steer Cursor and GitHub Copilot carries instructions the model follows and the
human reviewer cannot see. Invisible in the editor, invisible in a GitHub pull
request diff.

The propagation is the point: rule files get shared on forums, copied between
projects, contributed via PR, and bundled into starter templates. One poisoned
file backdoors every project that adopts it. GitHub has since added a warning when
a file contains hidden Unicode.

**This is why Slopguard scans your instruction files at session start rather than
trusting them.** The tool that reads `CLAUDE.md` cannot also be the tool that
vouches for it.

- [Pillar Security — Rules File Backdoor](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents) (March 2025)
- [CSA — README Injection: repository files hijacking AI coding assistants](https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/03/CSA_research_note_readme_instruction_injection_ai_coding_agents_20260317-csa-styled.pdf) (March 2026)

### Amazon Q Developer for VS Code v1.84.0

An inappropriately scoped GitHub token in a CodeBuild configuration let an
outsider land a commit in the extension's repository. The malicious payload — a
prompt instructing the assistant to wipe the filesystem and delete cloud resources
— shipped in the **official signed release on 17 July 2025** to an extension with
over 964,000 installs. Researchers found it on 23–24 July. AWS pulled 1.84.0 and
shipped 1.85.0.

It failed only because of a syntax error in the payload.

- [AWS security bulletin AWS-2025-015](https://aws.amazon.com/security/security-bulletins/AWS-2025-015/)
- [GitHub advisory GHSA-7g7f-ff96-5gcw](https://github.com/aws/aws-toolkit-vscode/security/advisories/GHSA-7g7f-ff96-5gcw)
- [ReversingLabs analysis](https://www.reversinglabs.com/blog/aws-amazonq-ai-incident)

---

## What this evidence actually argues

Not that AI coding tools are unsafe to use. The productivity gain is real and it
is not going away.

It argues something narrower and more actionable: **the failure modes are
consistent, well-documented, and mostly mechanical.** Hardcoded secrets, string-built
queries, missing object-level authorization, unverified packages, unread config
files. These are not subtle. They repeat because nothing in the generation loop
checks for them — and a check placed at the moment of generation costs a second,
while the same check placed after deployment costs an incident.

That is the entire thesis of this repository.
