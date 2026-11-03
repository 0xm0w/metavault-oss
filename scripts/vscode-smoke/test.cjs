/* eslint-disable @typescript-eslint/no-require-imports -- VS Code extension test runner loads CommonJS. */
const vscode = require('vscode');
const fs = require('fs');
exports.run = async () => {
  const log = message => fs.appendFileSync(process.env.MV_HOST_LOG, message + '\n');
  log('VS Code version: ' + vscode.version);
  log('Workspace trusted: ' + vscode.workspace.isTrusted);
  const until = Date.now() + 60000;
  let tool;
  while (Date.now() < until) {
    await vscode.commands.executeCommand('workbench.mcp.startServer', '*', {waitForLiveTools: true});
    tool = vscode.lm.tools.find(t => t.name.includes('metavault') && t.name.includes('request_capability'));
    if (tool) break;
    await new Promise(r => setTimeout(r, 1000));
  }
  log('Discovered tool names: ' + vscode.lm.tools.map(t => t.name).join(', '));
  if (!tool) throw Error('Actual VS Code host did not discover MetaVault capability tool');
  const result = await vscode.lm.invokeTool(tool.name, {input:{alias:'smoke-ci-credential',scope:'smoke',reason:'Synthetic installed VS Code host validation',tool:'windows-host-smoke'}});
  const text = result.content.map(p => p.value || '').join('\n');
  if (!text.includes('awaiting-approval')) throw Error('Host tool did not return authenticated pending capability: ' + text);
  log('PASS actual VS Code invoked installed MCP request_capability and received awaiting-approval');
};
