# Performance baseline

`cargo xtask benchmark` builds optimized `xtask` and `siorb` binaries, then
measures p95 search, resolver selection, and immutable plan construction against
a synthesized catalog exactly ten times the bundled catalog size, plus complete
`siorb --offline version` process startup and the Linux
worker's peak resident set from `/proc/self/status`. Inputs and absolute
regression ceilings live in `baseline.json`; the benchmark never rewrites that
file.

The committed reference runner is GitHub Actions `ubuntu-24.04` x86_64 with the
pinned Rust 1.85.0 toolchain. CI always enforces the ceilings. Locally,
`cargo xtask benchmark` reports measurements and `cargo xtask benchmark --check`
enforces them. Memory enforcement intentionally requires the Linux reference
runner; other platforms still execute all CPU and startup workloads and report
that RSS is unavailable.

The thresholds enforce p95 search below 150 ms, resolution below 50 ms, plan
generation below 250 ms, and startup below 100 ms on the reference runner.
The memory ceiling is measured only after constructing the 10× catalog. These
are broad absolute safety limits, not a claim that heterogeneous GitHub runners
have microbenchmark-grade stability.
Tighten them only from several recorded reference runs, and review any
relaxation as a performance regression decision.
