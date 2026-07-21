#!/usr/bin/env node
/**
 * SLOPGUARD / guard-write
 * PreToolUse on Write|Edit|MultiEdit|NotebookEdit.
 *
 * Inspects code in the instant between "the model produced it" and "it exists
 * on disk." This is the only moment where a vulnerability costs nothing to fix.
 * Every layer after this one — SAST, review, WAF — is paying interest on it.
 */

import { readHookInput, allow, decide, renderFindings, failOpen } from './io.mjs';
import { scanContent, isAllowlisted, findInvisible } from './rules.mjs';

try {
  const input = await readHookInput();
  const ti = input.tool_input || {};
  const filePath = ti.file_path || ti.notebook_path || '';

  if (isAllowlisted(filePath)) allow();

  // Gather every payload shape the edit tools use.
  const blobs = [];
  if (typeof ti.content === 'string') blobs.push(ti.content);
  if (typeof ti.new_string === 'string') blobs.push(ti.new_string);
  if (typeof ti.new_source === 'string') blobs.push(ti.new_source);
  if (Array.isArray(ti.edits)) {
    for (const e of ti.edits) if (typeof e?.new_string === 'string') blobs.push(e.new_string);
  }
  const content = blobs.join('\n');
  if (!content.trim()) allow();

  const findings = scanContent(content, filePath);

  // An agent writing invisible control characters into a file is either a
  // corrupted paste or an injected payload. Neither is something you want
  // silently committed.
  const invisible = findInvisible(content);
  if (invisible.length) {
    findings.unshift({
      id: 'SG-16',
      severity: 'deny',
      name: 'invisible Unicode control characters in generated content',
      evidence: invisible
        .slice(0, 3)
        .map((h) => `line ${h.line}: ${h.chars.join(', ')}`)
        .join(' | '),
      fix: 'Strip these characters. They are unreadable in review but are still read by the model — this is the "Rules File Backdoor" technique. If you did not intend them, the source you copied from is compromised.',
    });
  }

  if (!findings.length) allow();

  const denies = findings.filter((f) => f.severity === 'deny');
  const target = filePath || 'this file';

  if (denies.length) {
    decide(
      'deny',
      renderFindings(denies, `SLOPGUARD blocked this write to ${target} — ${denies.length} unsafe pattern(s):`),
    );
  }

  decide(
    'ask',
    renderFindings(findings, `SLOPGUARD flagged ${findings.length} pattern(s) in ${target} that need a human decision:`),
  );
} catch (err) {
  failOpen(err);
}
