// Static workflow text, never assembled from alias metadata or user input.
export const AGENT_INSTRUCTIONS = `Use MetaVault OSS through its MCP server named metavault.
- Never ask for or put secrets in chat, terminal output, logs, prompts, or IDE config.
- First call register_agent, tell the user the 6-digit code it returns, and ask them to approve the matching request in MetaVault OSS, then call registration_status. Verified means the user approved your credential; it is not proof of what program you are and grants no access. Never print or ask for any token.
- Call list_aliases to discover available credential aliases.
- Call request_capability with alias, scope, and reason. The vault executes the call or requests human approval; you never receive the secret.
- If the result is awaiting-approval, wait for it. request_capability waits briefly; then call grant_status with the grantId. When the user approves, the result of the call is returned to you once. If the status is denied, expired or revoked, stop, tell the user, and do not send the request again or look for another way.
- If a credential is missing, call request_enrollment. It opens MetaVault OSS on the user's computer with the add form ready (if launched is false, show its metavault:// link instead). Then poll enrollment_status. Only the user enters the secret in MetaVault OSS.
- Respect denials. Never approve requests, unlock the vault, or edit vault files yourself.
- If MCP is not connected, ask the user to open MetaVault OSS > Settings > Agent Integration & MCP and configure this host. Restart or reload the host's MCP connection after updating its config.
These instructions guide the agent; policy and human approval enforce access.`;
