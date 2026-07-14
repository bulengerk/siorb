# Build and inspect Siorb on macOS

No production release is published yet. Build from a reviewed checkout rather
than assuming a Homebrew formula or release archive exists.

## Prerequisites

- a currently supported macOS version on Intel or Apple Silicon;
- Xcode Command Line Tools and Git;
- Rust 1.85 through `rustup`.

```console
git clone https://github.com/bulengerk/siorb.git
cd siorb
rustup show active-toolchain
cargo build --locked --release -p siorb-cli
./target/release/siorb version
./target/release/siorb doctor --json
./target/release/siorb --dry-run --explain install firefox
```

The dry-run must not install. Inspect native architecture versus translation,
Homebrew formula/cask and MacPorts capability, source identity, scope, and any
privilege/agreement requirement. A package available on Intel may have no
reviewed Apple Silicon mapping and must remain unresolved rather than silently
changing source.

Release archives contain a signed binary when production signing is configured;
the `.pkg` is additionally signed, notarized, and stapled. A generated Homebrew
formula is downstream metadata and is not automatically present in a public tap.
