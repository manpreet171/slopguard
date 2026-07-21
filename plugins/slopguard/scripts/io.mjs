/** Shared stdin/stdout plumbing for Slopguard hooks. */

export async function readHookInput() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  const raw = Buffer.concat(chunks).toString('utf8').trim();
  if (!raw) return {};
  try {
    return JSON.parse(raw);
  } catch {
    return {};
  }
}

/** Let the tool call through untouched. */
export function allow() {
  process.exit(0);
}

/**
 * Stop the write and hand the agent a rule ID plus a concrete fix.
 * The agent reads `permissionDecisionReason`, so this text is the entire
 * teaching moment — make it actionable, not a scold.
 */
export function decide(permissionDecision, reason) {
  process.stdout.write(
    JSON.stringify({
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision,
        permissionDecisionReason: reason,
      },
    }),
  );
  process.exit(0);
}

/** Inject notes into the session without blocking anything. */
export function context(hookEventName, additionalContext, systemMessage) {
  const payload = { hookSpecificOutput: { hookEventName, additionalContext } };
  if (systemMessage) payload.systemMessage = systemMessage;
  process.stdout.write(JSON.stringify(payload));
  process.exit(0);
}

export function renderFindings(findings, header) {
  const lines = [header, ''];
  for (const f of findings) {
    lines.push(`• [${f.id}] ${f.name}`);
    if (f.evidence) lines.push(`    found: ${f.evidence}`);
    lines.push(`    fix:   ${f.fix}`);
    lines.push('');
  }
  lines.push('Rewrite the code to satisfy the rule above, then write the file again.');
  lines.push('Rule text lives in AGENTS.md. Do not disable the guard to get past it.');
  return lines.join('\n');
}

/** A guard that crashes must never wedge the user's session. */
export function failOpen(err) {
  process.stderr.write(`slopguard: ${err?.message || err}\n`);
  process.exit(0);
}
