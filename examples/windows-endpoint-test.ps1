#Requires -Version 7.0
<#
.SYNOPSIS
  Walrus managed-Windows endpoint checks — WAL-60 steps 1-4 and 6, WAL-68 step 1.

.DESCRIPTION
  These are the endpoint claims walrus makes and cannot verify anywhere else: that a served zip
  survives corporate antimalware, that Explorer's own zip handling extracts it, that git.exe and
  Git Bash run from the extracted tree, and that a multi-GB ranged download reassembles to the
  digest walrus publishes.

  Targets PowerShell 7. That is not a style preference: pwsh 7 runs on Linux too, so the
  transport half of this script — metadata, the ranged download, digest verification — is
  exercised on the dev workstation before the device exists. Only the genuinely Windows-only
  checks (Defender, the Explorer shell zip handler, git.exe, Git Bash) wait for hardware, and
  they SKIP cleanly rather than erroring when run elsewhere.

  Verified on Linux/pwsh 7.6.5 against GCP Dev, 2026-08-31: the download and digest paths pass.
  The Windows-only checks below them have NOT been executed anywhere yet — treat their first
  run on a real device as debugging the script as much as testing the endpoint.

  What deliberately stays human, and is NOT checked here:
    - WAL-60 step 5 — Git Credential Manager *prompting* and storing. Interactive by definition.
    - WAL-68 step 2 — IDEA launching and activating a licence against the corporate server.
    - WAL-68 step 6 — whether the retention window is the one the PO wanted.
  A green run of this script does not sign those off.

.PARAMETER WalrusUrl
  Base URL of the walrus deployment.

.PARAMETER WorkDir
  Scratch directory. Needs several GB free if -IncludeLargeArtifact.

.PARAMETER IncludeLargeArtifact
  Also run WAL-68 step 1: the ~1.6 GB IntelliJ ranged download. Slow, and the point.

.PARAMETER SshCloneUrl
  Optional. WAL-60 step 6: an SSH remote to clone with the extracted tree's git.

.EXAMPLE
  ./windows-endpoint-test.ps1 -WalrusUrl https://walrus-api-lh3bh3olnq-uc.a.run.app

.EXAMPLE
  ./windows-endpoint-test.ps1 -WalrusUrl <url> -IncludeLargeArtifact -SshCloneUrl git@host:org/repo.git
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string] $WalrusUrl,
  [string] $WorkDir = (Join-Path ([System.IO.Path]::GetTempPath()) "walrus-endpoint-test"),
  [switch] $IncludeLargeArtifact,
  [string] $SshCloneUrl
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$script:Pass = 0; $script:Fail = 0; $script:Skip = 0

function Write-Ok   ($Tag, $Msg) { Write-Host ("  PASS  {0,-8} {1}" -f $Tag, $Msg) -ForegroundColor Green;  $script:Pass++ }
function Write-No   ($Tag, $Msg) { Write-Host ("  FAIL  {0,-8} {1}" -f $Tag, $Msg) -ForegroundColor Red;    $script:Fail++ }
function Write-Skip ($Tag, $Msg) { Write-Host ("  SKIP  {0,-8} {1}" -f $Tag, $Msg) -ForegroundColor Yellow; $script:Skip++ }
function Write-Head ($Msg)       { Write-Host ""; Write-Host $Msg -ForegroundColor Cyan }

# ---------------------------------------------------------------------------------------------
# Metadata. Everything is driven by what walrus advertises, so the script cannot quietly assert
# against a stale expectation baked in here — including the version group, which rolls.
# ---------------------------------------------------------------------------------------------
function Get-WalrusArtifact {
  param([string] $Package, [string] $Os, [string] $Arch)

  $groups = (Invoke-RestMethod -Uri "$WalrusUrl/api/v1/packages/$Package/groups" -TimeoutSec 60).groups
  $first  = @($groups)[0]
  $group  = if ($first.PSObject.Properties.Name -contains 'version_group') { $first.version_group } else { $first.group }

  $r = Invoke-RestMethod -TimeoutSec 60 `
    -Uri "$WalrusUrl/api/v1/packages/$Package/versions/$group/latest?os=$Os&arch=$Arch"

  [pscustomobject]@{
    Version       = $r.version
    FileName      = $r.artifact.filename
    Size          = [int64] $r.artifact.file_size
    Checksum      = $r.artifact.checksum
    ChecksumType  = $r.artifact.checksum_type ?? 'sha256'
    RequiresRange = [bool] $r.artifact.requires_range
    Url           = "$WalrusUrl" + $r.artifact.download_url
  }
}

# Above walrus's size threshold an unranged GET is refused outright (400 range_required), so
# chunked ranging is the only way to fetch a large artifact — and it is what the product expects
# a client on this estate to do. Chunks stream straight into the output file: materialising a
# 32 MiB byte array per chunk would work, but it is exactly the accumulate-then-write habit that
# produced WAL-95 and WAL-97 on the server side.
function Get-ArtifactFile {
  param([object] $Artifact, [string] $OutFile, [int] $ChunkBytes = 33554432)

  if (Test-Path $OutFile) { Remove-Item $OutFile -Force }
  $client = [System.Net.Http.HttpClient]::new()
  $client.Timeout = [TimeSpan]::FromMinutes(10)
  $fs = [System.IO.File]::Create($OutFile)
  try {
    if (-not $Artifact.RequiresRange) {
      $stream = $client.GetStreamAsync($Artifact.Url).GetAwaiter().GetResult()
      $stream.CopyTo($fs)
      return
    }

    $have = 0L
    $etag = $null
    while ($have -lt $Artifact.Size) {
      $end = [Math]::Min($have + $ChunkBytes, $Artifact.Size) - 1
      $req = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Get, $Artifact.Url)
      $req.Headers.Range = [System.Net.Http.Headers.RangeHeaderValue]::new($have, $end)
      # If-Range from the second chunk on: if the artifact is re-synced mid-transfer the server
      # refuses rather than letting two builds be spliced into one file.
      if ($etag) { $req.Headers.TryAddWithoutValidation("If-Range", $etag) | Out-Null }

      $resp = $client.SendAsync($req).GetAwaiter().GetResult()
      if ($resp.StatusCode -ne [System.Net.HttpStatusCode]::PartialContent) {
        throw "expected 206 for bytes=$have-$end, got $([int]$resp.StatusCode)"
      }
      if (-not $etag -and $resp.Headers.ETag) { $etag = $resp.Headers.ETag.ToString() }

      $resp.Content.CopyToAsync($fs).GetAwaiter().GetResult()
      $have = $fs.Length
      Write-Progress -Activity "Downloading $($Artifact.FileName)" `
        -Status ("{0:N0} / {1:N0} bytes" -f $have, $Artifact.Size) `
        -PercentComplete ([Math]::Min(100, 100.0 * $have / $Artifact.Size))
    }
  } finally {
    $fs.Close(); $client.Dispose()
    Write-Progress -Activity "Downloading" -Completed
  }
}

function Test-Digest {
  param([string] $Tag, [string] $Path, [object] $Artifact, [string] $What)
  $actual = (Get-FileHash -Path $Path -Algorithm $Artifact.ChecksumType).Hash.ToLower()
  if (-not $Artifact.Checksum) {
    Write-No $Tag "$What — walrus published no digest to verify against (WAL-102)"
  } elseif ($actual -eq $Artifact.Checksum.ToLower()) {
    Write-Ok $Tag "$What — $($Artifact.ChecksumType) matches walrus's published digest"
  } else {
    Write-No $Tag "$What — digest mismatch: published $($Artifact.Checksum), got $actual"
  }
}

New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null
Write-Host "walrus endpoint check"
Write-Host "  target : $WalrusUrl"
Write-Host "  workdir: $WorkDir"
Write-Host "  host   : $([Environment]::MachineName)  PS $($PSVersionTable.PSVersion)  Windows=$IsWindows"
if (-not $IsWindows) {
  Write-Host "  note   : not Windows — transport checks run, endpoint checks skip" -ForegroundColor Yellow
}

# =============================================================================================
Write-Head "WAL-60 step 1 — download the served zip, and survive antimalware"
# =============================================================================================
# The premise of this package is that a zip gets through where the upstream .7z was quarantined.
# Two separate questions: did the bytes arrive intact, and did Defender take them away again.
$gitArtifact = $null
$gitZip      = $null
try {
  $gitArtifact = Get-WalrusArtifact -Package "gitwindows" -Os "windows" -Arch "x86-64"
  $gitZip = Join-Path $WorkDir $gitArtifact.FileName
  Get-ArtifactFile -Artifact $gitArtifact -OutFile $gitZip
  Write-Ok "WAL-60" "downloaded $($gitArtifact.FileName) ($('{0:N0}' -f $gitArtifact.Size) bytes)"
  Test-Digest -Tag "WAL-60" -Path $gitZip -Artifact $gitArtifact -What "served zip"
} catch {
  Write-No "WAL-60" "download failed: $($_.Exception.Message)"
}

# Quarantine-after-download looks exactly like success right up until the file is gone.
if ($gitZip -and (Test-Path $gitZip)) {
  Write-Ok "WAL-60" "file still present after download — not quarantined"
} elseif ($gitZip) {
  Write-No "WAL-60" "file disappeared after download — quarantined?"
}

if ($IsWindows) {
  try {
    $threats = @(Get-MpThreatDetection -ErrorAction Stop |
      Where-Object { $_.InitialDetectionTime -gt (Get-Date).AddMinutes(-30) })
    if ($threats.Count -gt 0) {
      Write-No "WAL-60" "Defender logged $($threats.Count) detection(s) in the last 30 min — see Get-MpThreatDetection"
    } else {
      Write-Ok "WAL-60" "no Defender detections in the last 30 minutes"
    }
  } catch {
    Write-Skip "WAL-60" "Defender cmdlets unavailable: $($_.Exception.Message)"
  }
} else {
  Write-Skip "WAL-60" "Defender check needs Windows"
}

# =============================================================================================
Write-Head "WAL-60 step 2 — extract with Explorer's own zip handling"
# =============================================================================================
# Deliberately NOT Expand-Archive. The claim under test is about Windows Explorer's built-in zip
# handler — what a developer double-clicking the file actually invokes — whose path-length and
# permission behaviour differs from the cmdlet's.
$extractDir = Join-Path $WorkDir "git-extracted"
if (-not $IsWindows) {
  Write-Skip "WAL-60" "Explorer shell extraction needs Windows"
} elseif (-not ($gitZip -and (Test-Path $gitZip))) {
  Write-Skip "WAL-60" "no zip to extract"
} else {
  try {
    if (Test-Path $extractDir) { Remove-Item $extractDir -Recurse -Force }
    New-Item -ItemType Directory -Path $extractDir | Out-Null
    $shell    = New-Object -ComObject Shell.Application
    $zipItems = $shell.NameSpace($gitZip).Items()
    $expected = $zipItems.Count
    # 0x14 = no progress dialog (4) + yes-to-all (16). CopyHere is asynchronous — it returns
    # immediately and extraction continues — so the wait below is required, not defensive.
    $shell.NameSpace($extractDir).CopyHere($zipItems, 0x14)

    $deadline = (Get-Date).AddMinutes(20)
    do {
      Start-Sleep -Seconds 5
      $count = @(Get-ChildItem -Path $extractDir -Force).Count
    } while ($count -lt $expected -and (Get-Date) -lt $deadline)

    if ($count -ge $expected) {
      Write-Ok "WAL-60" "Explorer extracted $count top-level entries"
    } else {
      Write-No "WAL-60" "Explorer extraction incomplete: $count of $expected top-level entries"
    }
  } catch {
    Write-No "WAL-60" "Explorer extraction failed: $($_.Exception.Message)"
  }
}

# =============================================================================================
Write-Head "WAL-60 steps 3-4 — git.exe and Git Bash run from the extracted tree"
# =============================================================================================
$gitExe  = Join-Path $extractDir "cmd/git.exe"
$bashExe = Join-Path $extractDir "usr/bin/bash.exe"

if (-not $IsWindows) {
  Write-Skip "WAL-60" "git.exe and Git Bash need Windows"
} else {
  if (Test-Path $gitExe) {
    try {
      $ver = (& $gitExe --version 2>&1) -join " "
      # The served version is four-component (2.55.0.5); git.exe reports the three-component Git
      # version it embeds (2.55.0), so match on the prefix rather than on equality. This is the
      # same mismatch that gates CVEs wrongly — see WAL-78.
      $parts = @($gitArtifact.Version -split '\.')
      $base  = ($parts[0..([Math]::Min(2, $parts.Count - 1))]) -join '.'
      if ($ver -match [regex]::Escape($base)) {
        Write-Ok "WAL-60" "git.exe reports '$ver', consistent with served $($gitArtifact.Version)"
      } else {
        Write-No "WAL-60" "git.exe reports '$ver', expected to contain $base"
      }
    } catch {
      Write-No "WAL-60" "git.exe failed to run: $($_.Exception.Message)"
    }
  } else {
    Write-No "WAL-60" "cmd\git.exe not found in the extracted tree"
  }

  if (Test-Path $bashExe) {
    try {
      # The requirement MinGit could not meet. Non-interactive, but it proves the shell and its
      # runtime dependencies resolve from the extracted tree, which is what step 4 is about.
      $out = (& $bashExe -lc "echo walrus-bash-ok; uname -s" 2>&1) -join " "
      if ($out -match "walrus-bash-ok") {
        Write-Ok "WAL-60" "Git Bash runs from the extracted tree ($out)"
      } else {
        Write-No "WAL-60" "Git Bash produced unexpected output: $out"
      }
    } catch {
      Write-No "WAL-60" "Git Bash failed to run: $($_.Exception.Message)"
    }
  } else {
    Write-No "WAL-60" "usr\bin\bash.exe not found in the extracted tree"
  }
}

# =============================================================================================
Write-Head "WAL-60 step 6 — git clone over SSH (optional)"
# =============================================================================================
# Step 5 (HTTPS + Git Credential Manager) is deliberately absent: the claim there is that the
# credential helper *prompts* and stores, which is interactive and cannot be asserted.
if (-not $IsWindows) {
  Write-Skip "WAL-60" "SSH clone uses the extracted tree's git — needs Windows"
} elseif (-not $SshCloneUrl) {
  Write-Skip "WAL-60" "SSH clone not attempted — pass -SshCloneUrl to enable"
} elseif (-not (Test-Path $gitExe)) {
  Write-Skip "WAL-60" "no extracted git.exe to clone with"
} else {
  try {
    $cloneDir = Join-Path $WorkDir "ssh-clone"
    if (Test-Path $cloneDir) { Remove-Item $cloneDir -Recurse -Force }
    & $gitExe clone --depth 1 $SshCloneUrl $cloneDir 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0 -and (Test-Path (Join-Path $cloneDir ".git"))) {
      Write-Ok "WAL-60" "SSH clone succeeded using the extracted tree's git and bundled ssh.exe"
    } else {
      Write-No "WAL-60" "SSH clone failed (exit $LASTEXITCODE)"
    }
  } catch {
    Write-No "WAL-60" "SSH clone threw: $($_.Exception.Message)"
  }
}

# =============================================================================================
Write-Head "WAL-68 step 1 — the 1.6 GB IntelliJ artifact, ranged and verified"
# =============================================================================================
if (-not $IncludeLargeArtifact) {
  Write-Skip "WAL-68" "large artifact not fetched — pass -IncludeLargeArtifact (needs ~2 GB free)"
} else {
  try {
    $idea = Get-WalrusArtifact -Package "intellij" -Os "windows" -Arch "x86-64"
    if (-not $idea.RequiresRange) {
      Write-No "WAL-68" "artifact does not advertise requires_range; the ranged path is untested"
    }
    $ideaZip = Join-Path $WorkDir $idea.FileName
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Get-ArtifactFile -Artifact $idea -OutFile $ideaZip
    $sw.Stop()

    $len = (Get-Item $ideaZip).Length
    if ($len -eq $idea.Size) {
      Write-Ok "WAL-68" "assembled $('{0:N0}' -f $len) bytes in $([int]$sw.Elapsed.TotalSeconds)s"
    } else {
      Write-No "WAL-68" "assembled $len bytes, expected $($idea.Size)"
    }
    Test-Digest -Tag "WAL-68" -Path $ideaZip -Artifact $idea -What "reassembled artifact"
  } catch {
    Write-No "WAL-68" "large artifact check failed: $($_.Exception.Message)"
  }
}

# =============================================================================================
Write-Host ""
Write-Host "-------------------------------------------------------------"
Write-Host ("{0} passed, {1} failed, {2} skipped" -f $script:Pass, $script:Fail, $script:Skip)
Write-Host ""
Write-Host "Still requires a human, and is NOT covered by this run:" -ForegroundColor Yellow
Write-Host "  WAL-60 step 5 - Git Credential Manager prompts and stores (interactive)"
Write-Host "  WAL-68 step 2 - IDEA launches and activates its licence against the corporate server"
Write-Host "  WAL-68 step 6 - the PO accepts the retention window"
if ($script:Fail -gt 0) { exit 1 } else { exit 0 }
