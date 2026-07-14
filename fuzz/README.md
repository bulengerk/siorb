# Fuzzing

The fuzz package is intentionally outside the release workspace. Run a target
with a nightly toolchain and `cargo-fuzz`, for example:

```text
cargo +nightly fuzz run catalog_json -- -max_len=1048576
```

Current production-facing targets cover catalog JSON, bundle TOML,
`/etc/os-release`, ZIP/TAR/path archive inspection, typed backend command
specs, terminal sanitization, and policy URL/domain handling. Seed corpora
contain only inert data. Keep generated crashes out of Git and promote every
fixed crash into a deterministic regression test.

Backend output parsing still needs a target as soon as that production API
exposes a byte-oriented parser. A fuzz target must call the production parser;
a duplicate parser inside `fuzz/` does not count.
