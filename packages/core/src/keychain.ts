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
        ["add-generic-password", "-U", "-s", "openvault", "-a", "master-key", "-w", base64],
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
        ["store", "--label=OpenVault Master Key", "service", "openvault", "account", "master-key"],
        { input: base64, stdio: ["pipe", "pipe", "pipe"] },
      );
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
        ["find-generic-password", "-s", "openvault", "-a", "master-key", "-w"],
        { encoding: "utf8", stdio: ["pipe", "pipe", "pipe"] },
      ).trim();
    } else if (process.platform === "linux") {
      raw = execFileSync(
        "secret-tool",
        ["lookup", "service", "openvault", "account", "master-key"],
        { encoding: "utf8", stdio: ["pipe", "pipe", "pipe"] },
      ).trim();
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
        ["delete-generic-password", "-s", "openvault", "-a", "master-key"],
        { stdio: ["pipe", "pipe", "pipe"] },
      );
      return true;
    }
    if (process.platform === "linux") {
      execFileSync(
        "secret-tool",
        ["clear", "service", "openvault", "account", "master-key"],
        { stdio: ["pipe", "pipe", "pipe"] },
      );
      return true;
    }
    return false;
  } catch {
    return false;
  }
}
