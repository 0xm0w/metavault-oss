import { ipcMain } from "electron";
import { spawn } from "node:child_process";
import { join } from "node:path";
import { omitVaultSecrets } from "./child-env.js";

// Windows Hello prompt for the Electron main process. The renderer never
// sees the PIN. UserConsentVerifier shows the same Windows Hello PIN,
// face, or fingerprint prompt Windows uses for passkeys. The script text
// is fixed; mode and purpose are validated arguments, not interpolated.

export type WindowsHelloPurpose = "setup" | "unlock";
export type WindowsHelloMode = "availability" | "verify";

export type WindowsHelloLine =
  | "available"
  | "not-configured"
  | "unavailable"
  | "verified"
  | "canceled"
  | "failed";

const LINES: ReadonlySet<string> = new Set([
  "available",
  "not-configured",
  "unavailable",
  "verified",
  "canceled",
  "failed",
]);

const HELLO_SCRIPT = [
  "$Mode = '{{MODE}}'",
  "$Purpose = '{{PURPOSE}}'",
  '$ErrorActionPreference = "Stop"',
  "try {",
  "  $null = [Windows.Security.Credentials.UI.UserConsentVerifier, Windows.Security.Credentials.UI, ContentType = WindowsRuntime]",
  "  Add-Type -AssemblyName System.Runtime.WindowsRuntime",
  "  $asTask = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {",
  "    $_.ToString() -eq 'System.Threading.Tasks.Task`1[TResult] AsTask[TResult](Windows.Foundation.IAsyncOperation`1[TResult])'",
  "  } | Select-Object -First 1)",
  '  if ($null -eq $asTask) { throw "AsTask overload missing" }',
  "  $message = if ($Purpose -eq 'setup') { 'Confirm it is you to turn on the MetaVault lock' } else { 'Confirm it is you to unlock MetaVault' }",
  "  if ($Mode -eq 'availability') {",
  "    $type = [Windows.Security.Credentials.UI.UserConsentVerifierAvailability]",
  "    $op = [Windows.Security.Credentials.UI.UserConsentVerifier]::CheckAvailabilityAsync()",
  "  } else {",
  "    $type = [Windows.Security.Credentials.UI.UserConsentVerificationResult]",
  "    $op = [Windows.Security.Credentials.UI.UserConsentVerifier]::RequestVerificationAsync($message)",
  "  }",
  "  $task = $asTask.MakeGenericMethod($type).Invoke($null, @($op))",
  "  if (-not $task.Wait(110000)) { throw 'timed out' }",
  "  switch ([string]$task.Result) {",
  "    'Available' { Write-Output 'available' }",
  "    'Verified' { Write-Output 'verified' }",
  "    'Canceled' { Write-Output 'canceled' }",
  "    'NotConfiguredForUser' { Write-Output 'not-configured' }",
  "    'RetriesExhausted' { Write-Output 'failed' }",
  "    default { Write-Output 'unavailable' }",
  "  }",
  "} catch {",
  "  Write-Output 'failed'",
  "  exit 1",
  "}",
  "",
].join("\r\n");

export function classifyWindowsHelloOutput(stdout: string): WindowsHelloLine {
  const lines = stdout.split(/\r?\n/).map((line) => line.trim()).filter((line) => line.length > 0);
  const last = lines.length > 0 ? lines[lines.length - 1] : "";
  if (last !== undefined && LINES.has(last)) {
    return last as WindowsHelloLine;
  }
  return "failed";
}

export function isWindowsHelloPurpose(value: unknown): value is WindowsHelloPurpose {
  return value === "setup" || value === "unlock";
}

function powershellPath(): string {
  const root = process.env["SystemRoot"];
  if (typeof root === "string" && root.length > 0) {
    return join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
  }
  return "powershell.exe";
}

function helloScript(mode: WindowsHelloMode, purpose: WindowsHelloPurpose): string | null {
  if (mode !== "availability" && mode !== "verify") return null;
  if (purpose !== "setup" && purpose !== "unlock") return null;
  return HELLO_SCRIPT.replace("{{MODE}}", mode).replace("{{PURPOSE}}", purpose);
}

function runPowershell(mode: WindowsHelloMode, purpose: WindowsHelloPurpose, timeoutMs: number): Promise<string> {
  const script = helloScript(mode, purpose);
  if (script === null) return Promise.resolve("failed");
  const encoded = Buffer.from(script, "utf16le").toString("base64");
  return new Promise((resolve) => {
    const child = spawn(
      powershellPath(),
      ["-NoProfile", "-NonInteractive", "-STA", "-EncodedCommand", encoded],
      { windowsHide: true, env: omitVaultSecrets(process.env) },
    );
    let stdout = "";
    const timer = setTimeout(() => {
      child.kill();
    }, timeoutMs);
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      stdout += chunk;
    });
    child.on("error", () => {
      clearTimeout(timer);
      resolve("failed");
    });
    child.on("close", () => {
      clearTimeout(timer);
      resolve(stdout);
    });
  });
}

export async function queryWindowsHello(mode: WindowsHelloMode, purpose: WindowsHelloPurpose): Promise<WindowsHelloLine> {
  if (process.platform !== "win32") {
    return "unavailable";
  }
  if (helloScript(mode, purpose) === null) {
    return "failed";
  }
  try {
    const timeoutMs = mode === "verify" ? 120_000 : 8_000;
    const stdout = await runPowershell(mode, purpose, timeoutMs);
    return classifyWindowsHelloOutput(stdout);
  } catch {
    return "failed";
  }
}
export function registerWindowsHelloIpc(): void {
  ipcMain.handle("metavault:windows-hello-availability", async () => {
    const reason = await queryWindowsHello("availability", "unlock");
    return { available: reason === "available", reason: reason === "verified" || reason === "canceled" ? "failed" : reason };
  });
  ipcMain.handle("metavault:windows-hello-verify", async (_event, purpose: unknown) => {
    if (!isWindowsHelloPurpose(purpose)) {
      return { ok: false, reason: "failed" };
    }
    const reason = await queryWindowsHello("verify", purpose);
    if (reason === "verified") return { ok: true, reason: "verified" };
    if (reason === "available") return { ok: false, reason: "failed" };
    return { ok: false, reason };
  });
}
