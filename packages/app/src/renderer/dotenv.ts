/**
 * Renderer-side .env file parser and credential inference.
 * Runs in the Electron renderer sandbox before secrets are sent to vaultd.
 */

export interface DotEnvImportItem {
  readonly rawKey: string;
  alias: string;
  scope: string;
  readonly value: string;
  included: boolean;
}

export function parseDotEnv(content: string): { key: string; value: string }[] {
  const entries: { key: string; value: string }[] = [];
  const lines = content.split(/\r?\n/);

  for (let i = 0; i < lines.length; i += 1) {
    let line = lines[i]?.trim();
    if (!line || line.startsWith("#")) {
      continue;
    }

    if (line.startsWith("export ")) {
      line = line.slice(7).trim();
    }

    const equalIdx = line.indexOf("=");
    if (equalIdx === -1) {
      continue;
    }

    const key = line.slice(0, equalIdx).trim();
    let val = line.slice(equalIdx + 1).trim();

    if (!key) {
      continue;
    }

    if (val.startsWith('"')) {
      let closed = false;
      let accum = val.slice(1);
      const closingQuote = findUnescapedQuote(accum, '"');
      if (closingQuote !== -1) {
        val = accum.slice(0, closingQuote);
        closed = true;
      } else {
        while (i + 1 < lines.length && !closed) {
          i += 1;
          const next = lines[i] ?? "";
          const nextQuote = findUnescapedQuote(next, '"');
          if (nextQuote !== -1) {
            accum += "\n" + next.slice(0, nextQuote);
            val = accum;
            closed = true;
          } else {
            accum += "\n" + next;
          }
        }
      }
      val = unescapeDoubleQuoted(val);
    } else if (val.startsWith("'")) {
      let closed = false;
      let accum = val.slice(1);
      const closingQuote = accum.indexOf("'");
      if (closingQuote !== -1) {
        val = accum.slice(0, closingQuote);
        closed = true;
      } else {
        while (i + 1 < lines.length && !closed) {
          i += 1;
          const next = lines[i] ?? "";
          const nextQuote = next.indexOf("'");
          if (nextQuote !== -1) {
            accum += "\n" + next.slice(0, nextQuote);
            val = accum;
            closed = true;
          } else {
            accum += "\n" + next;
          }
        }
      }
    } else {
      const commentIdx = val.indexOf(" #");
      if (commentIdx !== -1) {
        val = val.slice(0, commentIdx).trim();
      }
    }

    entries.push({ key, value: val });
  }

  return entries;
}

function findUnescapedQuote(str: string, quoteChar: string): number {
  for (let i = 0; i < str.length; i += 1) {
    if (str[i] === quoteChar) {
      let backslashes = 0;
      let j = i - 1;
      while (j >= 0 && str[j] === "\\") {
        backslashes += 1;
        j -= 1;
      }
      if (backslashes % 2 === 0) {
        return i;
      }
    }
  }
  return -1;
}

function unescapeDoubleQuoted(str: string): string {
  return str
    .replace(/\\n/g, "\n")
    .replace(/\\r/g, "\r")
    .replace(/\\t/g, "\t")
    .replace(/\\"/g, '"')
    .replace(/\\\\/g, "\\");
}

const KNOWN_RULES = [
  { match: /^STRIPE_/i, alias: "stripe", scope: "charges.read" },
  { match: /^OPENAI_/i, alias: "openai", scope: "chat.completions" },
  { match: /^ANTHROPIC_/i, alias: "anthropic", scope: "messages.create" },
  { match: /^(GITHUB_|GH_)/i, alias: "github", scope: "repo.read" },
  { match: /^AWS_/i, alias: "aws", scope: "s3.read" },
  { match: /^SUPABASE_/i, alias: "supabase", scope: "db.read" },
  { match: /^(POSTGRES_|DATABASE_|DB_)/i, alias: "database", scope: "db.read" },
  { match: /^REDIS_/i, alias: "redis", scope: "cache.read" },
  { match: /^SLACK_/i, alias: "slack", scope: "chat.write" },
  { match: /^TWILIO_/i, alias: "twilio", scope: "messages.send" },
  { match: /^SENDGRID_/i, alias: "sendgrid", scope: "mail.send" },
  { match: /^RESEND_/i, alias: "resend", scope: "mail.send" },
  { match: /^CLOUDFLARE_/i, alias: "cloudflare", scope: "dns.read" },
  { match: /^DISCORD_/i, alias: "discord", scope: "bot.read" },
  { match: /^PINECONE_/i, alias: "pinecone", scope: "vectors.read" },
  { match: /^HUGGING_?FACE_/i, alias: "huggingface", scope: "inference.run" },
  { match: /^COHERE_/i, alias: "cohere", scope: "generate.run" },
  { match: /^MISTRAL_/i, alias: "mistral", scope: "chat.completions" },
  { match: /^GOOGLE_|GEMINI_/i, alias: "gemini", scope: "generateContent" },
];

export function inferAliasAndScope(key: string): { readonly alias: string; readonly scope: string } {
  for (const rule of KNOWN_RULES) {
    if (rule.match.test(key)) {
      return { alias: rule.alias, scope: rule.scope };
    }
  }

  let cleaned = key
    .replace(/_(API_)?KEY$/i, "")
    .replace(/_(API_)?SECRET(_KEY)?$/i, "")
    .replace(/_(AUTH_)?TOKEN$/i, "")
    .replace(/_PASSWORD$/i, "")
    .replace(/_PRIVATE_KEY$/i, "")
    .replace(/_CREDENTIALS?$/i, "")
    .toLowerCase()
    .replace(/[_]/g, "-")
    .replace(/[^a-z0-9-]/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "");

  if (!cleaned || /^(key|secret|token)$/i.test(cleaned)) {
    cleaned = "credential";
  }

  return {
    alias: cleaned,
    scope: "read",
  };
}

export function parseDotEnvWithInference(content: string): DotEnvImportItem[] {
  const entries = parseDotEnv(content);
  return entries.map((entry) => {
    const { alias, scope } = inferAliasAndScope(entry.key);
    return {
      rawKey: entry.key,
      alias,
      scope,
      value: entry.value,
      included: true,
    };
  });
}
