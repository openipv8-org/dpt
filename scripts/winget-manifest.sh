#!/usr/bin/env bash
# winget-manifest.sh - write the winget manifest for a dpt release.
#
#   scripts/winget-manifest.sh v0.3.1
#
# It reads the release's SHA256SUMS from GitHub and writes the three files
# winget wants to packaging/winget/manifests/o/OpenIPv8/dpt/<version>/.
# To publish: copy that folder to the same place in a fork of
# github.com/microsoft/winget-pkgs and open a pull request (or run
# "wingetcreate submit <folder>" on Windows).  "winget validate <folder>"
# checks it first.
set -euo pipefail

tag=${1:?usage: winget-manifest.sh vX.Y.Z}
case $tag in v[0-9]*.[0-9]*.[0-9]*) ;; *) echo "winget-manifest.sh: $tag is not vX.Y.Z" >&2; exit 1 ;; esac
ver=${tag#v}
id=OpenIPv8.dpt
base=https://github.com/openipv8-org/dpt/releases/download/$tag
root=$(cd "$(dirname "$0")/.." && pwd)
out=$root/packaging/winget/manifests/o/OpenIPv8/dpt/$ver
schema=1.9.0

sums=$(curl -fsSL "$base/SHA256SUMS")
sum() {
	local s
	s=$(printf '%s\n' "$sums" | awk -v f="$1" '$2 == f { print toupper($1) }')
	[ ${#s} -eq 64 ] || { echo "winget-manifest.sh: no SHA-256 for $1 in $tag's SHA256SUMS" >&2; exit 1; }
	printf '%s' "$s"
}
x64=$(sum dpt-windows-amd64.exe)
arm64=$(sum dpt-windows-arm64.exe)
date=$(curl -fsSL "https://api.github.com/repos/openipv8-org/dpt/releases/tags/$tag" |
	sed -n 's/.*"published_at": *"\([0-9-]*\)T.*/\1/p' | head -1)

mkdir -p "$out"

cat >"$out/$id.yaml" <<EOF
# yaml-language-server: \$schema=https://aka.ms/winget-manifest.version.$schema.schema.json
PackageIdentifier: $id
PackageVersion: $ver
DefaultLocale: en-US
ManifestType: version
ManifestVersion: $schema
EOF

cat >"$out/$id.installer.yaml" <<EOF
# yaml-language-server: \$schema=https://aka.ms/winget-manifest.installer.$schema.schema.json
PackageIdentifier: $id
PackageVersion: $ver
InstallerType: portable
Commands:
- dpt
MinimumOSVersion: 10.0.0.0
ReleaseDate: ${date:-$(date -u +%Y-%m-%d)}
Installers:
- Architecture: x64
  InstallerUrl: $base/dpt-windows-amd64.exe
  InstallerSha256: $x64
- Architecture: arm64
  InstallerUrl: $base/dpt-windows-arm64.exe
  InstallerSha256: $arm64
ManifestType: installer
ManifestVersion: $schema
EOF

cat >"$out/$id.locale.en-US.yaml" <<EOF
# yaml-language-server: \$schema=https://aka.ms/winget-manifest.defaultLocale.$schema.schema.json
PackageIdentifier: $id
PackageVersion: $ver
PackageLocale: en-US
Publisher: OpenIPv8
PublisherUrl: https://github.com/openipv8-org
PublisherSupportUrl: https://github.com/openipv8-org/dpt/issues
Author: Jamie Thain
PackageName: DPT - Diagnostic Ports Time
PackageUrl: https://github.com/openipv8-org/dpt
License: MIT
LicenseUrl: https://github.com/openipv8-org/dpt/blob/main/LICENSE
ShortDescription: Network diagnostics in one tool - DNS, ping, time, ports, mail, trace - with an nslookup-style shell.
Description: |-
  dpt answers the questions of a network morning from one program: does the address answer ping,
  does it resolve and serve DNS, is the clock right (NTP against Google, Microsoft, AWS, Apple
  and NIST), which ports and UDP services are open, does its mail server work from here and over
  which ports, which routers are on the way, and what DHCP hands out. Run with no arguments it is
  an nslookup-style shell with dpt's commands added.
Moniker: dpt
Tags:
- dns
- network
- nslookup
- ntp
- ping
- port-scanner
- smtp
- traceroute
- dhcp
- diagnostics
ReleaseNotesUrl: https://github.com/openipv8-org/dpt/releases/tag/$tag
ManifestType: defaultLocale
ManifestVersion: $schema
EOF

echo "wrote $out"
ls -1 "$out"
