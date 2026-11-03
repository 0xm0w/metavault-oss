import { execFileSync } from "node:child_process";

export interface KeychainService {
  readonly storeMasterKey: (key: Buffer) => boolean;
  readonly retrieveMasterKey: () => Buffer | null;
  readonly deleteMasterKey: () => boolean;
}

export function storeMasterKey(key: Buffer): boolean {
  if (key.length !== 32) {
    throw new Error("masterKey must be 32 bytes");
  }
  const base64 = key.toString("base64");

  if (process.platform === "darwin") {
    try {
      // Use macOS security tool to store generic password in login keychain.
      // -U updates existing item if present, avoiding duplicate key errors.
      execFileSync(
        "security",
        ["add-generic-password", "-U", "-s", "metavault", "-a", "master-key", "-w", base64],
        { stdio: ["pipe", "pipe", "pipe"] },
      );
      return true;
    } catch {
      return false;
    }
  }

  if (process.platform === "linux") {
    try {
      execFileSync(
        "secret-tool",
        ["store", "--label=MetaVault OSS Master Key", "service", "metavault", "account", "master-key"],
        { input: base64, stdio: ["pipe", "pipe", "pipe"] },
      );
      return true;
    } catch {
      return false;
    }
  }

  if (process.platform === "win32") {
    try {
      const script = [
        "$null = [Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]",
        "$base64 = ($input | Out-String).Trim()",
        "$vault = New-Object Windows.Security.Credentials.PasswordVault",
        "try { $existing = $vault.Retrieve('metavault','master-key'); $vault.Remove($existing) } catch { }",
        "$cred = New-Object Windows.Security.Credentials.PasswordCredential('metavault','master-key',$base64)",
        "$vault.Add($cred)",
      ].join("\n");
      execFileSync("powershell", ["-NoProfile", "-Command", script], {
        input: base64,
        stdio: ["pipe", "pipe", "pipe"],
      });
      return true;
    } catch {
      return false;
    }
  }

  return false;
}

export function retrieveMasterKey(): Buffer | null {
  try {
    let raw = "";
    if (process.platform === "darwin") {
      raw = execFileSync(
        "security",
        ["find-generic-password", "-s", "metavault", "-a", "master-key", "-w"],
        { encoding: "utf8", stdio: ["pipe", "pipe", "pipe"] },
      ).trim();
    } else if (process.platform === "linux") {
      raw = execFileSync(
        "secret-tool",
        ["lookup", "service", "metavault", "account", "master-key"],
        { encoding: "utf8", stdio: ["pipe", "pipe", "pipe"] },
      ).trim();
    } else if (process.platform === "win32") {
      const script = [
        "$null = [Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]",
        "$vault = New-Object Windows.Security.Credentials.PasswordVault",
        "try {",
        "  $cred = $vault.Retrieve('metavault','master-key')",
        "  $cred.RetrievePassword()",
        "  Write-Output $cred.Password",
        "} catch { }",
      ].join("\n");
      try {
        raw = execFileSync("powershell", ["-NoProfile", "-Command", script], {
          encoding: "utf8",
          stdio: ["pipe", "pipe", "pipe"],
        }).trim();
      } catch {
        return null;
      }
    } else {
      return null;
    }

    const decoded = Buffer.from(raw, "base64");
    return decoded.length === 32 ? decoded : null;
  } catch {
    return null;
  }
}

export function deleteMasterKey(): boolean {
  try {
    if (process.platform === "darwin") {
      execFileSync(
        "security",
        ["delete-generic-password", "-s", "metavault", "-a", "master-key"],
        { stdio: ["pipe", "pipe", "pipe"] },
      );
      return true;
    }
    if (process.platform === "linux") {
      execFileSync(
        "secret-tool",
        ["clear", "service", "metavault", "account", "master-key"],
        { stdio: ["pipe", "pipe", "pipe"] },
      );
      return true;
    }
    if (process.platform === "win32") {
      const script = [
        "$null = [Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]",
        "$vault = New-Object Windows.Security.Credentials.PasswordVault",
        "try { $cred = $vault.Retrieve('metavault','master-key'); $vault.Remove($cred) } catch { }",
      ].join("\n");
      execFileSync("powershell", ["-NoProfile", "-Command", script], {
        stdio: ["pipe", "pipe", "pipe"],
      });
      return true;
    }
    return false;
  } catch {
    return false;
  }
}
