# Build and inspect Siorb on Windows

No production release is published yet. Build from a reviewed checkout instead
of inventing a release download URL.

## Prerequisites

- Windows 10/11 or a supported Windows Server edition;
- Git;
- Rust 1.85 through `rustup` with the MSVC target;
- Visual Studio Build Tools with the Desktop development with C++ workload.

In PowerShell:

```powershell
git clone https://github.com/bulengerk/siorb.git
Set-Location siorb
rustup show active-toolchain
cargo build --locked --release -p siorb-cli
.\target\release\siorb.exe version
.\target\release\siorb.exe doctor --json
.\target\release\siorb.exe --dry-run --explain install firefox
```

The last command must plan without installing. Review detected Windows version,
architecture, available WinGet/Scoop/Chocolatey capabilities, exact source,
scope, agreements, and privilege before running a mutating command. Executable
presence alone does not make a backend available.

The current executor has no validated Windows elevation broker. Detection
therefore reports user scope only and `external_elevation_unavailable`; a plan
that needs an elevated external command fails closed. Do not interpret UAC
being enabled as an executable Siorb elevation path.

The release pipeline also prepares a ZIP and WiX MSI. They are installable
artifacts only after a real release provides matching SHA-256, provenance,
signature, and Authenticode verification evidence. See the
[release runbook](../release-process.md).
