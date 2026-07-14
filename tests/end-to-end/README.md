# Host-safe end-to-end scenarios

`scenarios.json` is the canonical cross-platform CLI scenario matrix. The
runner must replace `PATH`, state, catalog, policy, HOME/application-data, and
network transport with per-test temporary fixtures. It must never discover or
invoke a package manager from the host.

`scenario_contract.rs` executes every host-safe row through production
components and also verifies the CLI JSON parse-error envelope.

The successful native-install row copies a test-only backend into a temporary
directory, creates its installed-state marker there, verifies the parseable
query result, and commits a receipt under temporary Siorb state. Its
`state_changed: true` means disposable fixture and receipt state changed; it
does not invoke a host package manager, so `requires_mutation` remains `false`.

Real package-manager install/verify/remove coverage is separate: the manually
dispatched `.github/workflows/native-smoke.yml` runs only on disposable GitHub
hosted Linux, macOS, and Windows runners. Any future matrix row that can mutate
the host must declare `requires_mutation: true` and remain outside the default
host-safe runner.
