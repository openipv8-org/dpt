# windows-test.ps1 - test dpt fully on this Windows PC.
#
# In PowerShell (a normal one, not "Run as administrator"):
#   irm https://raw.githubusercontent.com/openipv8-org/dpt/main/scripts/windows-test.ps1 | iex
#
# 1. Downloads the newest release of dpt for this PC (x64 or ARM64) from
#    github.com/openipv8-org/dpt, a test pre-release included, into
#    %USERPROFILE%\dpt and checks it against SHA256SUMS.  Nothing is built.
# 2. Runs every command as a script would (no terminal): help, version,
#    bad usage, ping, DNS, time, JSON, info (clock, outside IPv4 and IPv6),
#    dhcp (must refuse without asking), smtp (the mail check, the verdict),
#    ports (TCP, a list, UDP), connect (a banner, TLS), trace, outside-ip,
#    sweep, and the shell (server, fallback=, lserver, root, set all).
#    Each one checks its exit code and what it must say.
# 3. Then the parts that need you, each with a y/n question: Tab and the
#    arrows in the shell, smtp prompt (and its answers kept in .dpt),
#    typing to a mail server with connect, dhcp typed (UAC), the download
#    installing itself when double-clicked, install and upgrade.
# 4. Saves the log as %USERPROFILE%\dpt\windows-test.log and puts it on
#    the clipboard to paste back.  No password goes in the log.
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
Say "PowerShell $($PSVersionTable.PSVersion)"

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
Remove-Item (Join-Path $Dir 'SHA256SUMS')
Unblock-File (Join-Path $Dir $Bin)
# dpt.exe for the tests; the download name is kept for the double-click test
Copy-Item -Force (Join-Path $Dir $Bin) (Join-Path $Dir 'dpt.exe')
$D = Join-Path $Dir 'dpt.exe'

# Invoke-Dpt runs dpt with its input and output redirected, so dpt sees
# no terminal, as when run from a script; stdin is what it reads.  The
# output goes to the log and to $script:Out.
$script:Out = ''
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
	$script:Out = $out.Result + $err.Result
	Add-Content -Path $Log -Value $script:Out -Encoding UTF8
	return $p.ExitCode
}

$script:Pass = 0
$script:Fail = 0
$script:Failed = @()
function Result([string]$title, [bool]$ok, [string]$why) {
	if ($ok) {
		Say "--- $why`: PASS"
		$script:Pass++
	} else {
		Say "--- $why`: FAIL"
		$script:Fail++
		$script:Failed += $title
	}
}

# Check: what the output must say ($has) and must not ($hasnt)
function Check([string[]]$has, [string[]]$hasnt) {
	$miss = @()
	foreach ($h in $has) { if (-not $script:Out.Contains($h)) { $miss += "lacks '$h'" } }
	foreach ($h in $hasnt) { if ($script:Out.Contains($h)) { $miss += "says '$h'" } }
	return $miss
}

# Run <title> <expected exit codes> <args...> [must say] [must not say]:
# output to the log, so dpt sees no terminal (as from a script)
function Run([string]$title, [int[]]$want, [string[]]$a, [string[]]$has = @(), [string[]]$hasnt = @()) {
	Say ''
	Say "=== $title"
	Say "> dpt $($a -join ' ')"
	$t = [Diagnostics.Stopwatch]::StartNew()
	$code = Invoke-Dpt $a
	$secs = [math]::Round($t.Elapsed.TotalSeconds, 1)
	$miss = Check $has $hasnt
	$why = "exit $code (expected $($want -join ' or ')) in $secs s"
	if ($miss.Count -gt 0) { $why += '; ' + ($miss -join '; ') }
	Result $title (($want -contains $code) -and $miss.Count -eq 0) $why
}

# Ask: a y/n question about what was seen; y passes
function Ask([string]$title, [string]$q) {
	$a = Read-Host "$q (y/n)"
	Say "$q $a"
	Result $title ($a -match '^\s*y') "answer $a"
}

# Typed <args...>: dpt in this window, as a person runs it (its input and
# output are this window's, not captured); gives its exit code
function Typed([string[]]$a) {
	$sp = @{ FilePath = $D; NoNewWindow = $true; Wait = $true; PassThru = $true }
	if ($a.Count -gt 0) { $sp.ArgumentList = $a }
	$p = Start-Process @sp
	return $p.ExitCode
}

Say ''
Say '##### 1. as a script would run it'

Run 'version' 0 @('/version') @("dpt $Tag")
Run 'help' 0 @('/?') @('DPT - Diagnostic Ports Time', 'smtp prompt')
Run 'bad usage' 3 @('/bogus')
Run 'two targets' 3 @('1.1.1.1', '8.8.8.8')
Run 'all tests on 1.1.1.1' 0 @('1.1.1.1', '/c:3') @('PING', 'DNS')
Run 'ping only, verbose' 0 @('8.8.8.8', '/p', '/c:3', '/verbose') @('PING')
Run 'DNS only on 1.1.1.1' 0 @('1.1.1.1', '/d', '/c:3') @('DNS')
Run 'time only, time.apple.com as the target' 0 @('time.apple.com', '/t')
Run 'a name with every IPv4 address' 0 @('one.one.one.one', '/4', '/all', '/c:2')
Run 'a dead address (must FAIL)' 1 @('192.0.2.1', '/p', '/c:2', '/w:1')
Run 'JSON' 0 @('1.1.1.1', '/tdp', '/c:2', '/json') @('"target"')
Run 'info: interfaces, DNS, NTP, the clock, outside IPv4 and IPv6' 0 @('info') @('SYSTEM', 'CLOCK', 'OUTSIDE', 'IPv4', 'IPv6') @('MEL')
Run 'info as JSON' 0 @('info', '/json') @('"outside"')
if ($admin) {
	Run 'dhcp from a script, as Administrator (runs)' @(0, 1) @('dhcp', '/td')
} else {
	Run 'dhcp from a script (must not ask; a plain dpt: message)' 2 @('dhcp') @('dpt: dhcp needs') @('MEL')
}
Run 'smtp alone (must show how to use it)' 3 @('smtp') @('smtp prompt')
Run 'smtp: the mail check of mail.smtp2go.com (no login, nothing sent)' @(0, 1) @('smtp', 'mail.smtp2go.com') @('PORT 25', 'PORT 2525', 'PORT 8025', 'FROM HERE', 'VERDICT')
Run 'ports: the common TCP ports and UDP services of 1.1.1.1' @(0, 1) @('ports', '1.1.1.1') @('TARGET')
Run 'ports: a list, TCP and UDP' @(0, 1) @('ports', '1.1.1.1', '53,443,853,53/udp,123/udp') @('TARGET')
Run 'connect: a mail server greeting (piped: reads it and closes)' @(0, 1) @('connect', 'mail.smtp2go.com', '25') @('CONNECT', '220')
Run 'connect: TLS on 443' @(0, 1) @('connect', '1.1.1.1', '443') @('CONNECT', 'TLS')
Run 'trace 8.8.8.8 (Windows ICMP with TTL)' @(0, 1) @('trace', '8.8.8.8') @('TARGET', '8.8.8.8')
Run 'outside-ip' 0 @('outside-ip') @('OUTSIDE')
Run 'sweep: ping this network (a /24 takes a while)' @(0, 1) @('sweep') @('NETWORK')

Say ''
Say '=== shell: server, fallback=, lserver, root, set all'
$shellIn = @(
	'set type=mx', 'ietf.org', 'set type=a', 'google.com 1.1.1.1',
	'server 192.0.2.1', 'www.google.com',
	'set fallback clear', 'www.google.com',
	'lserver 1.1.1.1', 'www.google.com',
	'set fallback=8.8.8.8',
	'ping 1.1.1.1 2', 'set all',
	'root', 'server clear', 'time time.apple.com', 'info', 'exit'
) -join "`n"
$sx = Invoke-Dpt @() ($shellIn + "`n")
$miss = Check @(
	'mail exchanger',
	'*** [192.0.2.1] is not working: falling back to [8.8.8.8]',
	'fallback cleared: lookups go to the server only',
	'no servers could be reached',
	'falling back to [1.1.1.1]',
	'Default server: 192.0.2.1',
	'fallback = 8.8.8.8',
	'Default server: a.root-servers.net',
	'OUTSIDE'
) @('MEL')
$why = "exit $sx"
if ($miss.Count -gt 0) { $why += '; ' + ($miss -join '; ') }
Result 'shell' ($sx -eq 0 -and $miss.Count -eq 0) $why

Say ''
Say '##### 2. the parts that need you'

Say ''
Say '=== the shell at a terminal: Tab, the arrows, colour'
Write-Host ''
Write-Host 'dpt opens its shell here. Try: type ser then Tab (it should finish "server"),'
Write-Host 'press Enter, type info and Enter, then the Up arrow (it should bring back "info"),'
Write-Host 'then type exit and Enter.'
Typed @() | Out-Null
Ask 'shell typed' 'Did Tab complete, the Up arrow bring back the last line, and OK / WARN show in colour (not junk like [32m)?'

Say ''
Say '=== smtp prompt, and its answers kept for next time'
Write-Host ''
Write-Host 'dpt asks what to test. Answer:  hostname: mail.smtp2go.com   username: -   from: -'
Write-Host '(That is the mail check with no login and nothing sent. You may use your own'
Write-Host 'smtp2go login instead, to try the login and a test message; the password is not logged.)'
Typed @('smtp', 'prompt') | Out-Null
$dotdpt = Join-Path $env:APPDATA 'dpt\.dpt'
if (Test-Path $dotdpt) {
	$keys = (Get-Content $dotdpt | Where-Object { $_ -match '^smtp\.' } | ForEach-Object { ($_ -split '=', 2)[0] }) -join ' '
	$hostLine = Get-Content $dotdpt | Where-Object { $_ -match '^smtp\.host=' }
	Say "$dotdpt holds: $keys ($hostLine)"
	Result 'smtp prompt kept in .dpt' ($hostLine -match 'smtp2go') "$dotdpt written"
} else {
	Result 'smtp prompt kept in .dpt' $false "$dotdpt missing"
}
Write-Host ''
Write-Host 'Once more: just press Enter at each question; it should offer what you typed.'
Typed @('smtp', 'prompt') | Out-Null
Ask 'smtp prompt typed' 'Did it ask line by line with the colons in one column, end with FROM HERE and VERDICT, and the second time offer <mail.smtp2go.com>?'

Say ''
Say '=== connect: type to a mail server'
Write-Host ''
Write-Host 'dpt connects to mail.smtp2go.com port 25. Type:  EHLO test  and Enter (it answers 250 lines),'
Write-Host 'then  QUIT  and Enter (it says goodbye and closes).'
Typed @('connect', 'mail.smtp2go.com', '25') | Out-Null
Ask 'connect typed' 'Did you see the 220 greeting, 250 lines after EHLO, and did QUIT close it?'

Say ''
Say '=== dhcp typed at the prompt: dpt asks Windows (UAC), the result shows here'
if ($admin) {
	Say '(skipped: this PowerShell is already Administrator; run the test from a normal one to see UAC)'
} else {
	Write-Host 'Windows will ask "Do you want to allow this app to make changes?": click Yes.'
	$dx = Typed @('dhcp', '/td')
	Say "--- dhcp exit $dx (0 or 1 means it ran; 2 means it could not)"
	Ask 'dhcp typed' 'Did the UAC box appear, and the DHCP result print above in this window, with no other window?'
}

Say ''
Say '=== the download installs itself when double-clicked'
$inst = Join-Path $env:ProgramFiles 'dpt\dpt.exe'
$before = 'none'
if (Test-Path $inst) { $before = ((& $inst /version) -split ' ')[1] }
Say "installed before: $before"
Write-Host ''
Write-Host "Explorer opens with $Bin selected. Double-click it. A window opens and says it installs"
Write-Host 'itself (Windows asks UAC: click Yes), or that this version is already installed.'
Write-Host 'It then waits: press Enter in it to close it. Then come back here.'
Start-Process explorer.exe "/select,`"$(Join-Path $Dir $Bin)`""
Read-Host 'Press Enter here when that window has closed' | Out-Null
$after = 'none'
if (Test-Path $inst) { $after = ((& $inst /version) -split ' ')[1] }
Say "installed after: $after"
Result 'double-click install' ($after -eq $Tag) "Program Files\dpt is $after (want $Tag)"
Ask 'double-click window' 'Did the window say it installs itself (or that it was already installed), and wait for Enter before closing?'

Say ''
Say '=== install (copies dpt to Program Files\dpt and adds that to PATH)'
if ($admin) {
	$ix = Invoke-Dpt @('install')
} else {
	Write-Host 'Windows will ask again (UAC), to install: click Yes.'
	$ix = Typed @('install')
}
$got = 'missing'
if (Test-Path $inst) { $got = ((& $inst /version) -split ' ')[1] }
Result 'install' ($ix -eq 0 -and $got -eq $Tag) "install exit $ix, $inst is $got (want $Tag)"
Run 'upgrade (the newest is installed: must say up to date, never go back)' 0 @('upgrade') @('up to date')

Say ''
Say "SUMMARY: $script:Pass passed, $script:Fail failed"
if ($script:Fail -gt 0) { Say ("failed: " + ($script:Failed -join '; ')) }
Say "dpt $Tag   program: $D   log: $Log"
try {
	Get-Content $Log -Raw | Set-Clipboard
	Write-Host 'The log is on the clipboard: paste it back.'
} catch {
	Write-Host "Open $Log and paste it back."
}
