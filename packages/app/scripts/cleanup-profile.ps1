# Installed uninstaller helper. Never accepts a user-supplied deletion path.
$ErrorActionPreference = 'Stop'
try {
  # This historical key is shared by unregistered custom vaults. There is no
  # owner/dependency metadata. Refuse BEFORE deletion instead of orphaning them.
  $null = [Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]
  $vault = New-Object Windows.Security.Credentials.PasswordVault
  $all = @()
  try { $all = @($vault.RetrieveAll()) } catch {
    # PasswordVault reports ERROR_NOT_FOUND when it contains no entries.
    # Other errors mean ownership is unknown and must stop the wipe.
    if ($_.Exception.HResult -ne -2147023728) { throw }
  }
  foreach ($credential in $all) {
    if ($credential.Resource -eq 'metavault' -and $credential.UserName -eq 'master-key') {
      throw 'A shared legacy MetaVault key exists. No vault data was deleted. Back up and migrate its dependent vaults before uninstalling.'
    }
  }
  $root = Join-Path ([Environment]::GetFolderPath('ApplicationData')) 'MetaVault OSS'
  if (Test-Path -LiteralPath $root) {
    # Walk one directory at a time, refusing links BEFORE descending into them.
    $queue = New-Object 'System.Collections.Generic.Queue[string]'
    $queue.Enqueue($root)
    while ($queue.Count -gt 0) {
      $current = $queue.Dequeue()
      $item = Get-Item -LiteralPath $current -Force
      if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Refusing a linked vault directory' }
      foreach ($child in Get-ChildItem -LiteralPath $current -Force) {
        if (($child.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Refusing a linked vault entry' }
        if ($child.PSIsContainer) { $queue.Enqueue($child.FullName) }
      }
    }
    Remove-Item -LiteralPath $root -Recurse -Force
    if (Test-Path -LiteralPath $root) { throw 'Vault directory still exists' }
  }
  exit 0
} catch {
  Write-Output $_.Exception.Message
  exit 1
}
