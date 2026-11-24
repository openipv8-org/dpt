# Download dpt

Every link below always gets the **latest release**
([all releases](https://github.com/openipv8-org/dpt/releases),
[SHA256SUMS](https://github.com/openipv8-org/dpt/releases/latest/download/SHA256SUMS)).

| System | Download | Tested |
|---|---|---|
| Windows, most PCs (Intel/AMD) | [dpt-windows-amd64.exe](https://github.com/openipv8-org/dpt/releases/latest/download/dpt-windows-amd64.exe) | ✅ yes, on a Windows PC |
| Windows on ARM (Snapdragon, Surface Pro X) | [dpt-windows-arm64.exe](https://github.com/openipv8-org/dpt/releases/latest/download/dpt-windows-arm64.exe) | ⚠️ **not tested** (built, never run on one) |
| Mac, Apple Silicon (M1 and later) | [dpt-darwin-arm64](https://github.com/openipv8-org/dpt/releases/latest/download/dpt-darwin-arm64) | ⚠️ **not tested** (no Apple Silicon Mac to test on) |
| Mac, Intel | [dpt-darwin-amd64](https://github.com/openipv8-org/dpt/releases/latest/download/dpt-darwin-amd64) | ✅ yes, macOS 13 (an early version; the newer commands not yet) |
| Linux, Intel/AMD | [dpt-linux-amd64](https://github.com/openipv8-org/dpt/releases/latest/download/dpt-linux-amd64) | ✅ yes, Debian 13 |
| Linux, ARM (Raspberry Pi 64-bit, ARM servers) | [dpt-linux-arm64](https://github.com/openipv8-org/dpt/releases/latest/download/dpt-linux-arm64) | ⚠️ **not tested** (built, never run on one) |

"Not tested" means the program is built the same way from the same code,
but nobody has run it on that kind of machine yet. It should work; if it
does not, please [open an issue](https://github.com/openipv8-org/dpt/issues).

## 🙏 Have one of these? Please test it

**Mac Apple Silicon, Windows on ARM and Linux on ARM have never been tested.** If you have one, please pull the repo, run the test, and send us the results in an [issue](https://github.com/openipv8-org/dpt/issues/new) (paste or attach the log).

**Mac, Apple Silicon (M1 and later)**, in Terminal:

```
git clone https://github.com/openipv8-org/dpt ~/dpt     # or, if you have it: git -C ~/dpt pull
bash ~/dpt/scripts/mac-test.sh
```

The results are in `~/dpt/mac-test.log`. At the end it tries to copy the log to our test machine. Press Ctrl-C there; that step is only for us.

**Windows on ARM**, in PowerShell (a normal one, not "Run as administrator"):

```
irm https://raw.githubusercontent.com/openipv8-org/dpt/main/scripts/windows-test.ps1 | iex
```

When it finishes, the results are on the clipboard. Paste them into the issue.

**Linux on ARM**:

```
curl -fsSL https://raw.githubusercontent.com/openipv8-org/dpt/main/scripts/install.sh | bash
dpt version; dpt 1.1.1.1; dpt info; dpt ports 1.1.1.1; dpt trace 1.1.1.1; sudo dpt dhcp
```

Paste what it prints into the issue.

Thank you!

## Install

**Linux and Mac**, the easy way (checks SHA256SUMS, puts dpt in
`/usr/local/bin`, asks for your password):

```
curl -fsSL https://raw.githubusercontent.com/openipv8-org/dpt/main/scripts/install.sh | bash
```

**Or download** the file for your system above and run it with nothing
after it: it installs itself (asking for sudo, or UAC on Windows), then
says to open a new terminal and type `dpt`.

- **Windows:** double-click it. SmartScreen may say "Windows protected
  your PC": click More info, then Run anyway (dpt is not signed yet).
- **Mac:** `chmod +x dpt-darwin-arm64` (or `-amd64`), then right-click it
  and Open, the first time, since it is not signed yet.
- **Linux:** `chmod +x dpt-linux-amd64 && ./dpt-linux-amd64`

Once installed, `dpt upgrade` gets the newest release.

See the [README](README.md) for what dpt does.
