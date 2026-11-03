<#
.SYNOPSIS
  Shared Ollama memory measurement, dot-sourced by eval-windows.ps1 and
  thesis-windows.ps1.

.DESCRIPTION
  Why this exists: an earlier eval reported 0.09 GiB "peak ollama RAM" while
  `ollama ps` showed a 17 GB model loaded. Two things caused the gap:
    1. Only processes named ollama* were summed. The model is served by a
       child runner process that Ollama spawns. Depending on the Ollama build
       the child can have a different image name, so name matching alone can
       miss it. This helper walks the full process tree under every ollama*
       process (Win32_Process.ParentProcessId) and sums all of it.
    2. Process RAM alone never shows weights that live in VRAM. So the helper
       also records what Ollama itself reports: /api/ps `size` (total bytes
       of the loaded model) and `size_vram` (bytes in GPU memory), plus the
       raw `ollama ps` SIZE and PROCESSOR (CPU/GPU split) columns, plus the
       change in system-wide used physical memory (Win32_OperatingSystem),
       plus nvidia-smi memory.used when nvidia-smi is on PATH.

  Every value printed is read from the OS or from Ollama at run time.
  Nothing is estimated.
#>

function Get-OllamaProcessTree {
  # Returns @(@{ Pid; ParentPid; Name }) for every ollama* process and all of
  # its descendants (any image name).
  $all = @(Get-CimInstance Win32_Process -Property ProcessId, ParentProcessId, Name -ErrorAction SilentlyContinue)
  $byParent = @{}
  foreach ($p in $all) {
    $pp = [int]$p.ParentProcessId
    if (-not $byParent.ContainsKey($pp)) { $byParent[$pp] = New-Object System.Collections.Generic.List[object] }
    $byParent[$pp].Add($p)
  }
  $seen = @{}
  $queue = New-Object System.Collections.Generic.Queue[object]
  foreach ($p in $all) { if ($p.Name -like "ollama*") { $queue.Enqueue($p) } }
  $out = New-Object System.Collections.Generic.List[object]
  while ($queue.Count -gt 0) {
    $p = $queue.Dequeue()
    $id = [int]$p.ProcessId
    if ($seen.ContainsKey($id)) { continue }
    $seen[$id] = $true
    $out.Add(@{ Pid = $id; ParentPid = [int]$p.ParentProcessId; Name = [string]$p.Name })
    if ($byParent.ContainsKey($id)) { foreach ($c in $byParent[$id]) { $queue.Enqueue($c) } }
  }
  return ,$out.ToArray()
}

function Get-SystemUsedBytes {
  try {
    $os = Get-CimInstance Win32_OperatingSystem -Property TotalVisibleMemorySize, FreePhysicalMemory
    return ([double]$os.TotalVisibleMemorySize - [double]$os.FreePhysicalMemory) * 1024.0
  } catch { return -1.0 }
}

function Get-NvidiaUsedMiB {
  $smi = Get-Command nvidia-smi -ErrorAction SilentlyContinue
  if (-not $smi) { return $null }
  try {
    $txt = (& nvidia-smi --query-gpu=memory.used --format=csv,noheader,nounits 2>$null | Out-String).Trim()
    $sum = 0.0
    foreach ($l in ($txt -split "`r?`n")) { if ($l.Trim() -match '^\d+(\.\d+)?$') { $sum += [double]$l.Trim() } }
    return $sum
  } catch { return $null }
}

function New-MemTracker([string]$ollamaUrl) {
  return @{
    OllamaUrl = $ollamaUrl
    Tree = @(); TreeAge = 999
    PeakWs = 0.0; PeakPriv = 0.0; Samples = 0
    PeakByPid = @{}; NamesByPid = @{}
    SysBaseline = (Get-SystemUsedBytes); PeakSysUsed = 0.0
    GpuBaselineMiB = (Get-NvidiaUsedMiB); PeakGpuMiB = $null
    PeakApiSize = 0.0; PeakApiVram = 0.0
  }
}

function Update-MemTracker($t) {
  # Re-walk the process tree every 4 samples (CIM is slower than Get-Process).
  if ($t.TreeAge -ge 4) { $t.Tree = Get-OllamaProcessTree; $t.TreeAge = 0 } else { $t.TreeAge = $t.TreeAge + 1 }
  $ws = 0.0; $priv = 0.0
  foreach ($n in $t.Tree) {
    try {
      $p = Get-Process -Id $n.Pid -ErrorAction Stop
      $ws += $p.WorkingSet64; $priv += $p.PrivateMemorySize64
      $key = "{0} (pid {1}, parent {2})" -f $n.Name, $n.Pid, $n.ParentPid
      $t.NamesByPid[$key] = $true
      if (-not $t.PeakByPid.ContainsKey($key) -or $p.PeakWorkingSet64 -gt $t.PeakByPid[$key]) { $t.PeakByPid[$key] = [double]$p.PeakWorkingSet64 }
    } catch { }
  }
  if ($ws -gt $t.PeakWs) { $t.PeakWs = $ws }
  if ($priv -gt $t.PeakPriv) { $t.PeakPriv = $priv }
  $sys = Get-SystemUsedBytes
  if ($sys -gt $t.PeakSysUsed) { $t.PeakSysUsed = $sys }
  if ($t.Samples % 4 -eq 0) {
    $g = Get-NvidiaUsedMiB
    if ($null -ne $g -and ($null -eq $t.PeakGpuMiB -or $g -gt $t.PeakGpuMiB)) { $t.PeakGpuMiB = $g }
    $api = Get-OllamaApiPs $t.OllamaUrl
    if ($api.Size -gt $t.PeakApiSize) { $t.PeakApiSize = $api.Size }
    if ($api.Vram -gt $t.PeakApiVram) { $t.PeakApiVram = $api.Vram }
  }
  $t.Samples = $t.Samples + 1
}

function Get-OllamaApiPs([string]$ollamaUrl) {
  # Sum over loaded models of /api/ps size and size_vram.
  $size = 0.0; $vram = 0.0; $lines = New-Object System.Collections.Generic.List[string]
  try {
    foreach ($m in @((Invoke-RestMethod -Uri "$ollamaUrl/api/ps" -TimeoutSec 5).models)) {
      if (-not $m) { continue }
      $size += [double]$m.size; $vram += [double]$m.size_vram
      $lines.Add(("{0}: size {1} bytes, size_vram {2} bytes" -f $m.name, $m.size, $m.size_vram))
    }
  } catch { $lines.Add("/api/ps unavailable: $($_.Exception.Message)") }
  return @{ Size = $size; Vram = $vram; Lines = $lines.ToArray() }
}

function Get-OllamaPsColumns([string]$psText) {
  # Parses `ollama ps` text output into NAME / SIZE / PROCESSOR per row.
  # Header: NAME  ID  SIZE  PROCESSOR  [CONTEXT]  UNTIL
  $rows = New-Object System.Collections.Generic.List[string]
  $lines = @($psText -split "`r?`n" | Where-Object { $_.Trim() -ne "" })
  if ($lines.Count -lt 2) { return ,$rows.ToArray() }
  $hdr = $lines[0]
  $iSize = $hdr.IndexOf("SIZE"); $iProc = $hdr.IndexOf("PROCESSOR")
  $iNext = -1
  foreach ($h in @("CONTEXT", "UNTIL")) { $ix = $hdr.IndexOf($h); if ($ix -gt $iProc -and ($iNext -lt 0 -or $ix -lt $iNext)) { $iNext = $ix } }
  if ($iSize -lt 0 -or $iProc -lt 0) { return ,$rows.ToArray() }
  foreach ($l in $lines[1..($lines.Count - 1)]) {
    $name = ($l -split '\s+')[0]
    $sz = if ($l.Length -gt $iSize) { $l.Substring($iSize, [math]::Min($iProc, $l.Length) - $iSize).Trim() } else { "" }
    $end = if ($iNext -gt 0) { [math]::Min($iNext, $l.Length) } else { $l.Length }
    $pr = if ($l.Length -gt $iProc) { $l.Substring($iProc, $end - $iProc).Trim() } else { "" }
    $rows.Add(("{0}: SIZE {1}, PROCESSOR {2}" -f $name, $sz, $pr))
  }
  return ,$rows.ToArray()
}

function Write-MemReport($t, [string]$psText, [int]$sampleMs, [scriptblock]$say) {
  $fmt = { param([double]$b) "{0:N2} GiB" -f ($b / 1GB) }
  & $say ("ollama process tree: {0} process(es) seen (ollama* plus all descendants by ParentProcessId)" -f $t.NamesByPid.Count)
  foreach ($k in ($t.PeakByPid.Keys | Sort-Object)) { & $say ("  {0}: OS PeakWorkingSet64 {1}" -f $k, (& $fmt $t.PeakByPid[$k])) }
  & $say ("peak tree RAM:    {0} working set, {1} private bytes (sampled sums, every {2} ms, {3} samples)" -f (& $fmt $t.PeakWs), (& $fmt $t.PeakPriv), $sampleMs, $t.Samples)
  if ($t.SysBaseline -ge 0) {
    & $say ("system used RAM:  peak {0}, {1} above the pre-load baseline (all processes, Win32_OperatingSystem)" -f (& $fmt $t.PeakSysUsed), (& $fmt ([math]::Max(0, $t.PeakSysUsed - $t.SysBaseline))))
  }
  & $say ("ollama /api/ps:   peak size {0} ({1} bytes), peak size_vram {2} ({3} bytes), so ~{4} not in VRAM" -f (& $fmt $t.PeakApiSize), $t.PeakApiSize, (& $fmt $t.PeakApiVram), $t.PeakApiVram, (& $fmt ([math]::Max(0, $t.PeakApiSize - $t.PeakApiVram))))
  if ($null -ne $t.PeakGpuMiB) {
    $base = if ($null -ne $t.GpuBaselineMiB) { $t.GpuBaselineMiB } else { 0 }
    & $say ("nvidia-smi:       peak memory.used {0:N0} MiB ({1:N0} MiB above pre-load baseline)" -f $t.PeakGpuMiB, ($t.PeakGpuMiB - $base))
  } else { & $say "nvidia-smi:       not on PATH (GPU memory not sampled)" }
  foreach ($r in (Get-OllamaPsColumns $psText)) { & $say ("ollama ps:        {0}" -f $r) }
  & $say "note: weights served from VRAM or from memory-mapped model files may not appear in a process's private bytes; use /api/ps size_vram, the PROCESSOR split and the system-wide delta together."
}
