# Installed uninstaller helper. Never accepts a user-supplied deletion path.
$ErrorActionPreference = 'Stop'
try {
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
  $null = [Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]
  $vault = New-Object Windows.Security.Credentials.PasswordVault
  $all = @()
  try { $all = @($vault.RetrieveAll()) } catch { }
  foreach ($credential in $all) {
    if ($credential.Resource -eq 'metavault' -and $credential.UserName -eq 'master-key') { $vault.Remove($credential) }
  }
  exit 0
} catch {
  Write-Output $_.Exception.Message
  exit 1
}
