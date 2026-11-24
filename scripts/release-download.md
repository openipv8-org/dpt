## ⬇ Download

| System | Download | Tested |
|---|---|---|
| Windows, most PCs (Intel/AMD) | [dpt-windows-amd64.exe](https://github.com/openipv8-org/dpt/releases/latest/download/dpt-windows-amd64.exe) | ✅ every release, on a Windows machine; and by hand |
| Windows on ARM (Snapdragon, Surface Pro X) | [dpt-windows-arm64.exe](https://github.com/openipv8-org/dpt/releases/latest/download/dpt-windows-arm64.exe) | ✅ every release, on a Windows ARM machine |
| Mac, Apple Silicon (M1 and later) | [dpt-darwin-arm64](https://github.com/openipv8-org/dpt/releases/latest/download/dpt-darwin-arm64) | ✅ every release, on an Apple Silicon Mac |
| Mac, Intel | [dpt-darwin-amd64](https://github.com/openipv8-org/dpt/releases/latest/download/dpt-darwin-amd64) | ✅ every release, on an Intel Mac; and by hand |
| Linux, Intel/AMD | [dpt-linux-amd64](https://github.com/openipv8-org/dpt/releases/latest/download/dpt-linux-amd64) | ✅ every release, on Ubuntu; and by hand on Debian |
| Linux, ARM (Raspberry Pi 64-bit, ARM servers) | [dpt-linux-arm64](https://github.com/openipv8-org/dpt/releases/latest/download/dpt-linux-arm64) | ✅ every release, on an ARM Linux machine |

Every release is tested before it is published, on a real machine of each
kind ([GitHub's runners](https://github.com/openipv8-org/dpt/actions/workflows/test.yml)):
the unit tests, then every command of the release's own files, checked for
its exit code and what it must say (`scripts/ci-test.sh`). A release is
published only when all six pass.

"By hand" adds what a robot cannot: typing at the shell, the sudo or UAC
prompt, double-clicking the download, and DHCP on a real office network.
Have an Apple Silicon Mac, a Windows ARM PC or an ARM Linux box? Try that
part and tell us in an [issue](https://github.com/openipv8-org/dpt/issues/new):

- **Mac:** `git clone https://github.com/openipv8-org/dpt ~/dpt` (or `git -C ~/dpt pull`), then `bash ~/dpt/scripts/mac-test.sh`; send `~/dpt/mac-test.log` (press Ctrl-C at the copy to our test machine at the end)
- **Windows:** in PowerShell, `irm https://raw.githubusercontent.com/openipv8-org/dpt/main/scripts/windows-test.ps1 | iex`; the results are on the clipboard
- **Linux:** install with the line below, then `dpt info; sudo dpt dhcp; dpt` (type `help`, then `exit`) and paste what it says

Linux and Mac, install or update:
`curl -fsSL https://raw.githubusercontent.com/openipv8-org/dpt/main/scripts/install.sh | bash`
