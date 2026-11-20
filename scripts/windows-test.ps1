# windows-test.ps1 - test dpt on this Windows PC.
#
# In PowerShell (a normal one, not "Run as administrator"):
#   irm https://raw.githubusercontent.com/openipv8-org/dpt/main/scripts/windows-test.ps1 | iex
#
# 1. Downloads the newest release of dpt for this PC (x64 or ARM64) from
#    github.com/openipv8-org/dpt, a test pre-release included, into
#    %USERPROFILE%\dpt and checks it against SHA256SUMS.  Nothing is built.
# 2. Runs the tests: help, version, bad usage, ping, DNS, time, JSON,
#    info, the shell, and dhcp (from a script: must refuse without
#    asking; typed: Windows asks UAC and the result comes back here).
# 3. Saves the log as %USERPROFILE%\dpt\windows-test.log and puts it on
#    the clipboard to paste back.
# The program is left as %USERPROFILE%\dpt\dpt.exe.

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$ProgressPreference = 'SilentlyContinue'

$Dir = Join-Path $env:USERPROFILE 'dpt'
New-Item -ItemType Directory -Force -Path $Dir | Out-Null
Set-Location $Dir
$Log = Join-Path $Dir 'windows-test.log'
Set-Content -Path $Log -Value '' -Encoding UTF8

function Say([string]$s) {
	Write-Host $s
	Add-Content -Path $Log -Value $s -Encoding UTF8
}

$arch = $env:PROCESSOR_ARCHITEW6432
if (-not $arch) { $arch = $env:PROCESSOR_ARCHITECTURE }
switch ($arch) {
	'AMD64' { $Bin = 'dpt-windows-amd64.exe' }
	'ARM64' { $Bin = 'dpt-windows-arm64.exe' }
	default { Say "no dpt build for $arch"; return }
}
# the newest release, a test pre-release included (releases/latest skips those)
try {
	$Tag = (Invoke-RestMethod -UseBasicParsing -Uri 'https://api.github.com/repos/openipv8-org/dpt/releases?per_page=1')[0].tag_name
} catch {
	Write-Host "cannot reach GitHub: $_"
	return
}
$Url = "https://github.com/openipv8-org/dpt/releases/download/$Tag"
$os = Get-CimInstance Win32_OperatingSystem
Say "dpt Windows test  $(Get-Date)"
Say "$($os.Caption) $($os.Version) $arch"
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Say "running as Administrator: $admin"

Say "downloading $Bin from release $Tag"
try {
	Invoke-WebRequest -UseBasicParsing -Uri "$Url/$Bin" -OutFile (Join-Path $Dir $Bin)
	Invoke-WebRequest -UseBasicParsing -Uri "$Url/SHA256SUMS" -OutFile (Join-Path $Dir 'SHA256SUMS')
} catch {
	Say "download failed from ${Url}: $_"
	return
}
$want = (Get-Content (Join-Path $Dir 'SHA256SUMS') | Where-Object { $_ -match " $([regex]::Escape($Bin))$" }) -replace '\s.*$', ''
$got = (Get-FileHash -Algorithm SHA256 (Join-Path $Dir $Bin)).Hash.ToLower()
if (-not $want -or $got -ne $want) {
	Say "checksum FAILED (want $want, got $got): not running it"
	Remove-Item (Join-Path $Dir $Bin), (Join-Path $Dir 'SHA256SUMS') -ErrorAction SilentlyContinue
	return
}
Say 'checksum OK'
Move-Item -Force (Join-Path $Dir $Bin) (Join-Path $Dir 'dpt.exe')
Remove-Item (Join-Path $Dir 'SHA256SUMS')
Unblock-File (Join-Path $Dir 'dpt.exe')
$D = Join-Path $Dir 'dpt.exe'

# Invoke-Dpt runs dpt with its input and output redirected, so dpt sees
# no terminal, as when run from a script; stdin is what it reads.
function Invoke-Dpt([string[]]$a, [string]$stdin = '') {
	$psi = New-Object System.Diagnostics.ProcessStartInfo $D
	$psi.Arguments = ($a -join ' ')
	$psi.UseShellExecute = $false
	$psi.RedirectStandardOutput = $true
	$psi.RedirectStandardError = $true
	$psi.StandardOutputEncoding = [Text.Encoding]::UTF8
	$psi.StandardErrorEncoding = [Text.Encoding]::UTF8
	$psi.RedirectStandardInput = $true
	$p = [Diagnostics.Process]::Start($psi)
	$out = $p.StandardOutput.ReadToEndAsync()
	$err = $p.StandardError.ReadToEndAsync()
	$p.StandardInput.Write($stdin)
	$p.StandardInput.Close()
	$p.WaitForExit()
	Add-Content -Path $Log -Value ($out.Result + $err.Result) -Encoding UTF8
	return $p.ExitCode
}

$script:Pass = 0
$script:Fail = 0
# Run <title> <expected exit codes> <args...>: output to the log, so dpt
# sees no terminal (as from a script)
function Run([string]$title, [int[]]$want, [string[]]$a) {
	Say ''
	Say "=== $title"
	Say "> dpt $($a -join ' ')"
	$code = Invoke-Dpt $a
	if ($want -contains $code) {
		Say "--- exit $code (expected $($want -join ' or ')): PASS"
		$script:Pass++
	} else {
		Say "--- exit $code (expected $($want -join ' or ')): FAIL"
		$script:Fail++
	}
}

Run 'version' 0 @('/version')
Run 'help' 0 @('/?')
Run 'bad usage' 3 @('/bogus')
Run 'two targets' 3 @('1.1.1.1', '8.8.8.8')
Run 'all tests on 1.1.1.1' 0 @('1.1.1.1', '/c:3')
Run 'ping only, verbose' 0 @('8.8.8.8', '/p', '/c:3', '/verbose')
Run 'DNS only on 1.1.1.1' 0 @('1.1.1.1', '/d', '/c:3')
Run 'time only, time.apple.com as the target' 0 @('time.apple.com', '/t')
Run 'a name with every IPv4 address' 0 @('one.one.one.one', '/4', '/all', '/c:2')
Run 'a dead address (must FAIL)' 1 @('192.0.2.1', '/p', '/c:2', '/w:1')
Run 'JSON' 0 @('1.1.1.1', '/tdp', '/c:2', '/json')
Run 'info (reads this PC, sends nothing)' 0 @('info')
if ($admin) {
	Run 'dhcp from a script, as Administrator (runs)' @(0, 1) @('dhcp', '/td')
} else {
	Run 'dhcp from a script (must not ask; says it needs an Administrator prompt)' 2 @('dhcp')
}

Say ''
Say '=== shell'
$sx = Invoke-Dpt @() "set type=mx`nietf.org`nset type=a`ngoogle.com 1.1.1.1`n8.8.8.8`nset all`nping 1.1.1.1 2`ntime time.apple.com`ninfo`nexit`n"
Say "--- shell exit $sx"

Say ''
Say '=== dhcp typed at the prompt: dpt asks Windows (UAC), the result shows here'
if ($admin) {
	Say '(skipped: this PowerShell is already Administrator; run the test from a normal one to see UAC)'
} else {
	Write-Host 'Windows will ask "Do you want to allow this app to make changes?": click Yes.'
	$ErrorActionPreference = 'Continue'
	& $D dhcp /td
	$dx = $LASTEXITCODE
	$ErrorActionPreference = 'Stop'
	Say "--- dhcp exit $dx (0 or 1 means it ran; 2 means it could not)"
	$seen = Read-Host 'Did the UAC box appear, and the DHCP result print above in this window, with no other window? (y/n)'
	Say "UAC and result in this window: $seen"
	$colour = Read-Host 'Were OK / WARN / FAIL in colour (not escape-code junk like [32m)? (y/n)'
	Say "colour shown properly: $colour"
}

Say ''
Say "SUMMARY: $script:Pass passed, $script:Fail failed (shell and typed dhcp: read the log)"
Say "program: $D   log: $Log"
try {
	Get-Content $Log -Raw | Set-Clipboard
	Write-Host 'The log is on the clipboard: paste it to spock.'
} catch {
	Write-Host "Open $Log and paste it to spock."
}
