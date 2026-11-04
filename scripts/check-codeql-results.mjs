// Fail closed on absent/partial CodeQL evidence or any actionable result.
// Do not print source snippets or result messages to logs.
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
const directory = process.argv[2];
if (!directory) throw new Error('CodeQL results directory required');
const files = readdirSync(directory).filter(name => name.endsWith('.sarif'));
if (!files.length) throw new Error('No CodeQL SARIF results produced');
let findings = 0;
for (const file of files) {
  const sarif = JSON.parse(readFileSync(join(directory, file), 'utf8'));
  if (sarif.version !== '2.1.0' || !Array.isArray(sarif.runs) || !sarif.runs.length) throw new Error('Invalid CodeQL SARIF evidence');
  for (const run of sarif.runs) {
    if (!Array.isArray(run.results)) throw new Error('Missing CodeQL result array');
    if (run.invocations?.some(invocation => invocation.executionSuccessful === false)) throw new Error('Incomplete CodeQL analysis');
    findings += run.results.length;
  }
}
console.log(`CodeQL SARIF files: ${files.length}; findings: ${findings}`);
if (findings) throw new Error('CodeQL findings require review before merge');
