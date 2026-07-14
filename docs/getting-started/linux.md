# Build and inspect Siorb on Linux

No production release is published yet. Build from a reviewed checkout rather
than assuming a repository package exists.

## Prerequisites

Install Git, a C toolchain/linker, and Rust 1.85 through `rustup` using your
distribution's trusted instructions. Siorb detects distribution identity from
stable OS files/APIs; installing a package-manager executable does not change
that identity.

```console
git clone https://github.com/bulengerk/siorb.git
cd siorb
rustup show active-toolchain
cargo build --locked --release -p siorb-cli
./target/release/siorb version
./target/release/siorb doctor --json
./target/release/siorb --dry-run --explain install firefox
```

The dry-run must not install or refresh native indexes. Review distribution
ancestry, architecture/libc, backend versions/capabilities, exact native package
ID, scope, and privilege. Debian/Ubuntu, Fedora/RHEL, Arch, openSUSE, and Alpine
have distinct mappings; a generic `linux` mapping does not override a more
specific incompatible source.

The release workflow prepares tar archives plus DEB/RPM metadata. A DEB/RPM is
not a promise of compatibility with every derivative; consult the tagged
[platform evidence](../platform-support.md) and verify checksums/signatures.
