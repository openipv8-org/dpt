# dpt in winget

The Windows Package Manager installs dpt as `OpenIPv8.dpt`, a portable
package: winget downloads the release's `dpt-windows-amd64.exe` (or
`arm64`), checks its SHA-256, and puts it on PATH as `dpt`.

```
winget install OpenIPv8.dpt
```

A dpt winget installed is winget's to keep: `dpt upgrade` runs
`winget upgrade --id OpenIPv8.dpt --exact`, and `dpt install` leaves it
where it is.

## A release

1. Release dpt as usual (the tag and its assets, SHA256SUMS among them).
2. Write the manifest from the release:

   ```
   scripts/winget-manifest.sh v0.3.2
   ```

   It goes in `packaging/winget/manifests/o/OpenIPv8/dpt/0.3.2/`: the
   version, installer and en-US locale files, checksums taken from the
   release's SHA256SUMS.
3. On Windows, check it: `winget validate <that folder>`, and try it:
   `winget install --manifest <that folder>`.
4. Submit it: fork `github.com/microsoft/winget-pkgs`, copy the folder to
   the same path (`manifests/o/OpenIPv8/dpt/0.3.2/`), and open a pull
   request; or on Windows, `wingetcreate submit <that folder>`.
   Microsoft's checks run on the pull request (the schema, the download,
   the checksum, a malware scan); a person reviews the first one.

Each release after that needs its own manifest and pull request.
