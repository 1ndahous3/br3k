# Development

Rust declarations, binding attributes, and `///` comments are the source of truth for the Python API. `cargo api` generates only `.pyi` files, including docstrings and public exports. MkDocs creates API pages in memory when building the site. Never edit generated stubs by hand.

## Local Tooling

Install [uv](https://docs.astral.sh/uv/getting-started/installation/), then run from the repository root:

```powershell
uv sync --locked
uv run --locked prek install
```

The root uv project owns the tool versions in `uv.lock`. Host Python is not pinned: uv selects a compatible interpreter according to `requires-python` in `pyproject.toml`. The minimum covers the tooling's use of `tomllib` and the documentation dependencies, independently of br3k's runtime. Documentation dependencies are an optional `docs` group. Git hooks are installed only by the explicit `prek install` command.

After changing Rust Python bindings:

```powershell
cargo api
uv run --locked prek run --all-files
```

The hooks check stub drift and run ty over all scripts, VM scenarios, stubs, and Python packaging tools. Documentation, stub, or documentation-tooling changes also trigger a strict MkDocs build using the `docs` dependency group. Hooks do not rewrite source files, stage changes, execute scenarios, or build the native CLI. Changing an API checks all consumers, not only modified scripts. The Cargo generator always runs in release mode.

`ty` is a static type checker, not a formatter or the embedded interpreter. It targets Windows and Python 3.15, matching the current RustPython language target. Local checks read `stubs/` directly. Config values injected by the CLI have explicit annotations at the script boundary; required globals still fail immediately when absent. Type checking does not validate external YAML values or replace functional system tests.

Use `scratch/` for local unfinished experiments; it is ignored by Git and outside the checked scenario directories.

Keep scenarios compact: annotate config boundaries and API objects, but let ty infer local expressions and iterator results. Small dynamic keyword-argument dictionaries may use `dict[str, Any]` instead of duplicating constructor calls or adding a matching `TypedDict`. This deliberately leaves the dictionary's argument names and value types unchecked at the call site; explicit arguments and returned API objects remain checked. Do not disable argument-type checking globally.

## Stub Wheel

```powershell
uv build --wheel
uv run --locked python tools/python/check_wheel.py dist/br3k_stubs-<version>-py3-none-any.whl
```

The wheel contains the PEP 561 `br3k-stubs` package, not an implementation of br3k. It has no runtime dependencies and works with type checkers on any host platform. It does not make `import br3k` executable in CPython.

Hatchling supplies the standard wheel backend; uv manages the environment and build. The version source retains the native staging scheme: `0.<UTC days since 2025-01-01>.0`. No tag, manual manifest edit, or lockfile update is needed for a staging build. `BR3K_VERSION` optionally overrides both native and wheel versions; CI computes it once for all jobs in a workflow. The wheel version source also accepts `SOURCE_DATE_EPOCH` for reproducible builds. Different staging artifacts may share a version and are distinguished by the CI run/commit.

The wheel check compares packaged stubs with the generated sources, installs the wheel in a temporary environment, and checks copied scenarios without access to source stubs. It also verifies that invalid API usage is rejected. No VM scenario is executed by this check.

## Documentation

```powershell
uv run --locked --group docs mkdocs build -f tools/docs/mkdocs.yml --strict
uv run --locked --group docs mkdocs serve -f tools/docs/mkdocs.yml
uv run --locked --group docs ty check --config "src.include=['tools/docs']"
```

The configuration and build-hook live in `tools/docs/`; the commands above run from the repository root. `docs/` contains only hand-written Markdown. The static site is written to `target/docs/`. The `tools/docs/reference.py` build-hook reads the stub modules and their `__all__` lists to create virtual `api/` pages; there are no intermediate Markdown files under `docs/api/`. MkDocs uses its bundled theme; mkdocstrings parses the stubs without importing br3k or starting a VM. `mkdocs serve` watches the stubs for changes. API signatures and docstrings come from the same generated files used by ty and the wheel. Hand-written Markdown covers workflows and architecture, not a second API reference.

## Release Tests

On Windows with the project's Rust/MSVC toolchain:

```powershell
cargo build --release --workspace
cargo test --release --workspace --no-fail-fast
```

Build native artifacts before host tests, using the same target architecture. x86 tests currently require `-- --test-threads=1`; ARM64 tests can only be compiled with `--no-run` on the x64 runner. See [Testing](https://github.com/1ndahous3/br3k/blob/main/tests/README.md) for fixture ownership and failure artifacts.

CI runs static checks, packaging validation, and documentation separately from native release tests. Normal builds upload the wheel and HTML; tag releases additionally attach the wheel to the GitHub release. PyPI and documentation hosting are not enabled.
