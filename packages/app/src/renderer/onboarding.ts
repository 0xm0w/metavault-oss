// Static workflow text, never assembled from alias metadata or user input.
export const AGENT_INSTRUCTIONS = `Use MetaVault OSS through its MCP server named metavault.
- Never ask for or put secrets in chat, terminal output, logs, prompts, or IDE config.
- Call list_aliases to discover available credential aliases.
- Call request_capability with alias, scope, and reason. The vault executes the call or requests human approval; you never receive the secret.
- If a credential is missing, call request_enrollment, show its metavault:// link to the user, then poll enrollment_status. Only the user enters the secret in MetaVault OSS.
- Respect denials. Never approve requests, unlock the vault, or edit vault files yourself.
- If MCP is not connected, ask the user to open MetaVault OSS > Settings > Agent Integration & MCP and configure this host. Restart or reload the host's MCP connection after updating its config.
These instructions guide the agent; policy and human approval enforce access.`;
