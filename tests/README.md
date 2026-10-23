# Testing

Build artifacts with Cargo, then run tests with Cargo. Host tests execute the prebuilt CLI; they never invoke a compiler or download samples. All br3k binaries and native fixtures must be release builds for the same target architecture. No host Python installation is required.

## Layout

- `host/`: the `br3k-host-tests` Cargo package. Its integration tests manage processes, run the CLI, and validate artifacts without linking to the br3k library.
- `vm/`: standalone functional scenarios covering br3k features through its Python API and system interactions, with explicit config globals. They execute inside the CLI's embedded VM.
- `fixtures/`: the `br3k-test-fixtures` Cargo package. Its `pe-target` executable is an idle process for PE tests, with no dependency on br3k.
- `../scripts/`: user scenarios. Only explicitly listed PE examples are smoke-tested; adding a script does not opt it into execution.

The native fixture explicitly loads `ucrtbase.dll` before signalling readiness, independently of static/dynamic CRT linkage. Each process-based test gets its own copy of the executable and its own process. Host-owned processes are stopped in fixture teardown, including after failed assertions or CLI timeouts. Reconstructed PE files are parsed, never executed. VM scenarios are self-contained because the embedded runtime intentionally does not enable `host_env` or general filesystem imports.

## Test Scope

Each VM scenario exercises a coherent feature workflow, such as capturing and inspecting an image, recovering imports and validating the output, or checking file operations across strategies. Related assertions and edge cases belong within that scenario; do not add a separate VM script for each parameter or failure path. These scenarios test br3k functionality, not the Python language or RustPython runtime.

Use Rust unit tests for isolated algorithms and validation rules. Host tests manage native fixtures, invoke scenarios, and check their artifacts. Tests of host support code exercise config serialization and polling without VM scripts or native fixtures.

## Local Runs

Requires Windows and the project's Rust/MSVC toolchain. Build and test from the repository root:

```powershell
cargo build --release -p br3k-cli -p br3k-test-fixtures
cargo test --release --workspace --no-fail-fast
```

To run only host tests, use `cargo test --release -p br3k-host-tests`. Add a name filter such as `pe::`, `fs::`, `examples::`, or `recovery`. `cargo test --release -p br3k-host-tests -- --list` compiles the test executable and lists cases without launching scenarios. The `support::tests::` cases do not require CLI or fixture binaries. Missing required artifacts fail the affected tests rather than silently skipping them.

For another architecture, pass the same `--target <triple>` to both Cargo commands. The default binary directory is the profile directory containing the host test executable's `deps/` directory, including custom Cargo target directories. ARM64 cross-compilation alone is not a runtime test; use `cargo test --release --workspace --target aarch64-pc-windows-msvc --no-run` on x64.

Optional environment overrides:

- `BR3K_TEST_BIN_DIR`: directory containing the prebuilt `br3k-cli.exe` and `pe-target.exe`, useful when testing relocated artifacts or another runnable architecture.
- `BR3K_TEST_TIMEOUT`: positive integer timeout in seconds for each CLI invocation; defaults to 180.
- `BR3K_TEST_OUTPUT_DIR`: parent directory for isolated case directories; defaults to `target/test-runs/<host-architecture>` in the workspace. Existing directories are not cleared.

## Results

Each CLI invocation records its input config, stdout, and stderr in the case's temporary directory. Exceptions, nonzero exits, and timeouts fail the test; independent cases continue normally. Output text is diagnostic, not a generic pass/fail protocol. RAII guards stop and wait for owned processes on both success and panic, including CLI timeouts.

Successful cases remove their temporary directories. Failed cases retain configs, logs, and generated files, with the directory path printed in the failure output. Retained failures are not automatically pruned. CI uploads these directories; test results appear in the Cargo job log.

VM tests assert PE semantics, including IAT slot preservation and source immutability. Example tests validate emitted PE/YAML artifacts where available. Reporting-only examples deliberately catch some per-module errors, so their smoke checks prove completion, not complete semantic coverage; the dedicated VM tests provide stricter checks. Hidden/packed/malformed images still need their own controlled corpus.

## CI

The `tests` workflow runs on pull requests, branch pushes, and manual dispatch. It builds release artifacts, checks generated API files, and runs Rust plus host/VM tests on x64 and x86. ARM64 artifacts and test binaries are cross-compiled but not executed on the x64 runner. The separate release-packaging workflow is unchanged.

x86 Rust tests currently run serially (`-- --test-threads=1`) because an intermittent parallel RustPython crash remains under investigation. This is a temporary workaround, not a fix. Host tests use separate CLI processes. Injection scenarios are not part of the host suite and are never implicitly selected.

Git hooks are not installed automatically. Keep pre-commit checks static; use the same Cargo commands for an optional pre-push or manual smoke run after building release artifacts.
