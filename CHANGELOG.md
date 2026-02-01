# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and the project aspires to follow
Semantic Versioning for tagged releases.

## [Unreleased]
### Changed
- Make `translate` binary optional via `bins` feature flag.

## [0.2.0] - 2026-01-31

### Added
- Workspace maintenance crate `xtask`.
  - `update-ghidra <TAG>`: syncs `cpp/sleigh` and `cpp/processors` from a Ghidra tag.
  - `bench`: benchmarks pcode-rs; optional CSV output; side-by-side pypcode comparison.
  - Verification mode (`--verify`, `--verify-sample`, `--include-imark`) that
    compares canonicalized p-code across pcode-rs and pypcode.
  - Flags: `--python`, `--coverage`, `--max-insns`, `--iter-ops`, `--iter-varnodes`, `--csv`.

### Changed
- Performance: removed per-call `reset_context` after `translate()`/`disassemble()`
  in Rust; rely on `fastReset()` inside the C++ context for cheap resets.
  - Files: `src/context.rs`, `cpp/simple_context.cpp` (behavioral note).
- FFI: pass raw byte pointers to C++ (no `CString`/NUL requirement) for
  `translate()`/`disassemble()`.
  - File: `src/context.rs`.
- Bench: stop appending a trailing NUL byte when calling `translate()`.
  - File: `xtask/src/bench.rs`.

### Fixed
- Verification false negatives: aligned canonicalization between pcode-rs and
  pypcode (numeric opcode mapping, normalized address-space names, per-block
  UNIQUE offset remapping, masking LOAD/STORE spaceID constants, consistent
  formatting) so `--verify` yields stable results.
  - File: `xtask/src/bench.rs`.
- Eliminated major throughput regression caused by reconstructing Sleigh per
  block; pcode-rs lift performance is now comparable to pypcode on sampled
  binaries in `--release`.

### Notes
- Typical usage to run the benchmark:
  - `cargo run -p xtask --release -- bench -b <binary> --lang <id> [--python <interp>] [--verify]`
- Keep local changes to `cpp/sleigh`/`cpp/processors` committed before running
  `update-ghidra`, which replaces those directories.
