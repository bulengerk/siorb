# Packaging inputs

These files are source metadata, not prebuilt installers. `cargo xtask package`
is the preferred entry point; the scripts under `scripts/release/` are narrow
platform hooks used by that task and CI.

Release filenames use `siorb-VERSION-TARGET` with Rust target triples. Archives
contain `siorb`/`siorb.exe`, `README.md`, and `LICENSE`. Platform packages install
only the CLI and documentation; they do not add a daemon, service, telemetry, or
catalog server.

| Platform | Output | Source |
|---|---|---|
| Windows | x86-64/ARM64 ZIP and WiX MSI | `windows/siorb.wxs`, `package-windows.ps1` |
| Windows package index | x86-64/ARM64 WinGet multipart manifest | `windows/winget/*.yaml.in`, `generate_winget.py` |
| macOS | tar.gz and optional signed `.pkg` | `package-macos.sh`, `macos-sign-notarize.sh` |
| macOS package index | Homebrew formula | `macos/homebrew/siorb.rb.in`, `generate_homebrew.py` |
| Linux | tar.gz, DEB, RPM | `linux/debian/control.in`, `linux/rpm/siorb.spec`, `package-linux.sh` |

Native hooks require their platform tools: `dpkg-deb` and/or `rpmbuild` on
Linux; `pkgbuild`, `productsign`, `codesign`, `notarytool`, and `stapler` on
macOS; PowerShell 7, .NET, WiX 6, and Windows SDK `signtool.exe` on Windows.
The workflows install only public build tooling; signing identities are exposed
solely by protected environments.

Package creation is secret-free. Production signing is a separate operation;
see `docs/release-process.md`. Never test an installer on a contributor's host
from the default test suite—use a disposable VM/container and inspect package
contents first.

`scripts/release/test-packaging.sh` covers deterministic archives, verifier
security regressions, downstream metadata, and DEB reproducibility where
`dpkg-deb` exists. The secret-free `Native packaging` workflow additionally
builds and inspects RPM, WiX MSI, and macOS PKG outputs on their native x86-64
and ARM64 runners before a production tag is accepted.

`scripts/release/sign-artifacts.sh` uses keyless Sigstore identity when an OIDC
provider is present, or an explicit `SIORB_COSIGN_KEY` path/KMS URI for an
operator-controlled local key. It never embeds key material in a package.
