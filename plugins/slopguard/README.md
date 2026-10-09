# Slopguard

Security guardrails for code your AI writes, checked in the one second between
"the model produced it" and "it exists on disk."

- **Before a Write or Edit lands:** blocks hardcoded secrets, SQL built by string
  interpolation, dynamic shell and `eval`, unsafe deserialization and weak crypto.
  Each block hands the model a rule ID and a concrete fix, so it usually corrects
  itself on the next try. Heuristic patterns ask you instead of blocking.
- **Before an install command runs:** checks every npm and PyPI package name
  against the real registry. A package that doesn't exist is a hallucination, and
  the install doesn't happen (slopsquatting).
- **At session start:** flags invisible Unicode and prompt-injection phrases in
  your agent instruction files (`CLAUDE.md`, `AGENTS.md`, rules folders) and warns when an MCP or settings file
  changed since the last session (the MCPoison pattern).

Three skills (`/slopguard:threat-model`, `/slopguard:harden`,
`/slopguard:preflight`) and a red-team review agent (`@slopguard:redteam`) come with it.

## What it runs and touches

- **Hooks:** `PreToolUse` on Write, Edit, MultiEdit and NotebookEdit; `PreToolUse`
  on Bash; `SessionStart`. All are plain Node 18+ scripts using only the standard
  library.
- **Network:** only the Bash hook, and only for install commands. It asks
  `registry.npmjs.org` and `pypi.org` whether each package name exists. Only the
  package name is sent; your code never leaves your machine. If the registry
  doesn't answer in time, the install goes ahead (it fails open).
- **Writes:** one file, `config-baseline.json`, in Claude Code's plugin data folder,
  holding short hashes of your MCP and settings files so it can spot changes.
- No telemetry, no account, no API key. Nothing is sent to Singh Labs.

Every rule lives in one readable file, `scripts/rules.mjs`. It's a guardrail, not
a sandbox: code written through the shell instead of the Write tool isn't inspected.

Full documentation: https://github.com/manpreet171/slopguard ·
https://singhlabs.dev/slopguard/ · MIT licence.
