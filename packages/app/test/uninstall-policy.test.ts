import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
const hooks=readFileSync(new URL("../scripts/installer.nsh",import.meta.url),"utf8");
const cleanup=readFileSync(new URL("../scripts/cleanup-profile.ps1",import.meta.url),"utf8");
describe("explicit uninstall policy",()=>{
  it("warns before removal, allows Cancel, and never wipes on update",()=>{
    expect(hooks).toContain("!macro customUnInit");
    expect(hooks).toContain("MB_OKCANCEL|MB_ICONEXCLAMATION");
    expect(hooks).toContain("IfSilent wipe_notice_done");
    expect(hooks).toContain("${ifNot} ${isUpdated}");
    expect(hooks).toMatch(/!macro customUnInstall[\s\S]*\$\{ifNot\} \$\{isUpdated\}[\s\S]*cleanup-profile/);
    expect(hooks).not.toContain('RMDir /r "$APPDATA');
  });
  it("cleanup accepts no arbitrary path and rejects links before recursive removal",()=>{
    expect(cleanup).not.toContain("param(");
    expect(cleanup).toContain("'ApplicationData')) 'MetaVault OSS'");
    expect(cleanup.indexOf("ReparsePoint")).toBeLessThan(cleanup.indexOf("Remove-Item"));
    expect(cleanup.indexOf("A shared legacy MetaVault key exists")).toBeLessThan(cleanup.indexOf("Remove-Item"));
    expect(cleanup).not.toContain("$vault.Remove");
    expect(cleanup).toContain("$credential.Resource -eq 'metavault' -and $credential.UserName -eq 'master-key'");
  });
});
