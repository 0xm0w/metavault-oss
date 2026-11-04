// Agent instructions copied into IDE agents. Universal and IDE-neutral: any
// local MCP host can follow them. When the app's runtime paths are known
// (always in the installed app) they are baked in, so the prompt names this
// installation's actual vault endpoint, MCP launch command and config
// location. The prompt is assembled only from local runtime facts, never
// from alias metadata, user input, or secrets: the agent token stays a
// separate one-time value the user generates in the app.

export interface AgentInstructionsContext {
  readonly daemonUrl: string;
  readonly command: string;
  readonly args: readonly string[];
  readonly env: Record<string, string>;
  readonly dbPath: string;
}

const WORKFLOW = `How to work with the vault
- First call register_agent, tell the user the 6-digit code it returns, and ask them to approve the matching request in MetaVault OSS, then call registration_status. Verified means the user approved your credential; it is not proof of what program you are and grants no access. Never print or ask for any token.
- Call list_aliases to discover available credential aliases.
- Call request_capability with alias, scope, and reason. The vault executes the call or requests human approval; you never receive the secret.
- If the result is awaiting-approval, wait for it. request_capability waits briefly; then call grant_status with the grantId. When the user approves, the result of the call is returned to you once. If the status is denied, expired or revoked, stop, tell the user, and do not send the request again or look for another way.
- If a credential is missing, call request_enrollment. It opens MetaVault OSS on the user's computer with the add form ready (if launched is false, show its metavault:// link instead). Then poll enrollment_status. Only the user enters the secret in MetaVault OSS.
- Respect denials. Never approve requests, unlock the vault, or edit vault files yourself.`;

const RULES = `Rules that always apply
- Never ask for or put secrets in chat, terminal output, logs, prompts, or IDE config. The one exception is the METAVAULT_AGENT_TOKEN launch variable above, which the user pastes into your MCP config themselves.
- Everything is local: the vault daemon listens on 127.0.0.1 only while MetaVault OSS is open. Do not look for a remote endpoint.
- These instructions guide the agent; policy and human approval enforce access.`;

function connectionBlock(ctx: AgentInstructionsContext | null): string {
  if (ctx === null) {
    return `How to connect (works with any MCP host, not a specific IDE)
- Ask the user to open MetaVault OSS > Settings > Daemon > Agent Integration & MCP. There they generate or rotate the token for your host and copy a ready-made config for common hosts (Claude Code, Cursor, VS Code, Codex, OpenCode). Other hosts use the same launch details shown there.
- The vault daemon (vaultd) runs locally at http://127.0.0.1:7077 while MetaVault OSS is open.`;
  }
  const envLines = [
    `    ELECTRON_RUN_AS_NODE=${ctx.env["ELECTRON_RUN_AS_NODE"] ?? "1"}`,
    `    METAVAULT_DAEMON_URL=${ctx.daemonUrl}`,
    `    METAVAULT_AGENT_ID=<one id for your host, lowercase, e.g. opencode>`,
    `    METAVAULT_IDE=<your host's display name>`,
    `    METAVAULT_AGENT_TOKEN=<token for that agent id, from the app>`,
  ].join("\n");
  return `How to connect (works with any MCP host, not a specific IDE)
- Run MetaVault's MCP server as a local stdio process from this installation:
    command: ${ctx.command}
    arguments: ${ctx.args.join(" ")}
  with these environment variables:
${envLines}
- The token comes only from the user: MetaVault OSS > Settings > Daemon > Agent Integration & MCP, generate or rotate the token for your agent id. The same panel has ready-made configs for common hosts (Claude Code, Cursor, VS Code, Codex, OpenCode) with everything above already filled in. Tokens are shown once, at generation time.
- The vault daemon (vaultd) for this installation listens locally at ${ctx.daemonUrl} while MetaVault OSS is open. Vault data lives at ${ctx.dbPath}. Never read, edit, move or unlock vault files yourself.
- Pasting these instructions into a chat does NOT connect you. Connection happens only when your host launches the server above through its MCP configuration. After the config changes, the host must be restarted or its MCP connection reloaded.`;
}

export function buildAgentInstructions(ctx: AgentInstructionsContext | null): string {
  return `Use MetaVault OSS through its local MCP server (server name: metavault).

${connectionBlock(ctx)}

${WORKFLOW}

If your MCP tools (register_agent, request_capability, list_aliases, and the rest) are missing, you are not connected: stop and ask the user to finish the connection steps above in MetaVault OSS > Settings > Daemon > Agent Integration & MCP, then restart or reload your host's MCP connection. Do not improvise another route to the vault.

${RULES}`;
}

// Generic copy without machine-specific paths, for contexts where the
// runtime is unavailable (development builds before the daemon answers).
export const AGENT_INSTRUCTIONS = buildAgentInstructions(null);
