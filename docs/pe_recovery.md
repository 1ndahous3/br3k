# PE Analysis And Recovery

Use these routines only for authorized, non-malicious education, research, and testing.

`br3k.pe` provides process capture, PE inspection, comparison, and local reconstruction. Scripts select targets and present results; parsing and recovery run in Rust. These operations neither modify the target process nor execute reconstructed code.

See the [script guide](scripts.md) for ready-made scenarios and the [API reference](api/pe/index.md) or [Python stubs](../stubs/br3k/pe/__init__.pyi) for signatures, options, and returned records.

## Object Model

| Object | Responsibility | Entry point |
|---|---|---|
| `pe.ProcessView` | Module inventory, cached references and symbols, capture and scanning | `pe.ProcessView(process)` |
| `pe.Capture` | Acquired bytes, load address, source identity, unreadable ranges | `view.capture(module_or_candidate)` |
| `pe.Image` | Immutable parsed bytes with explicit file/mapped layout | `capture.image()`, `pe.Image(file_bytes)` |
| `pe.analysis.Comparison` | Matched capture/reference pair and shared normalization | `view.compare(capture)` |
| `pe.recovery.Plan` | Source-bound recovery analysis and editable import model | `view.recover(capture)` |
| `pe.Editor` | Transactional local edits grouped by feature | `image.edit()` |
| `pe.BuildResult` | Output image, complete/partial status, changes and diagnostics | `plan.build()` or `editor.build()` |

## Start With A Process

The examples assume `import br3k` and a running notepad.exe. The CLI initializes the system API before script execution.

```python
process = br3k.proc.Process(
    name="notepad.exe",
    process_open_strategy=br3k.proc.ProcessOpenStrategy.OpenProcess,
    process_vm_read_strategy=br3k.proc.ProcessVmReadStrategy.ReadVirtualMemory,
)
process.open()
process.init_memory()

view = br3k.pe.ProcessView(process)
capture = view.capture(view.modules[0])
image = capture.image()
```

`view.symbols` lazily builds an export index with aliases, forwarders, and API-set resolution. The default source policy tries disk exports, then mapped exports on failure; `view.source_errors` retains failures and fallback explanations. `view.reference(module_or_capture)` caches file reads, including failures.

`view.refresh()` replaces the module inventory and invalidates caches. Existing captures remain inspectable, but the view rejects stale or foreign captures for comparison and recovery. Acquisition is not an atomic OS snapshot.

## Capture And Layout

- `Capture` holds bytes and acquisition errors, not necessarily a valid PE. Use `capture.image()` to retain unreadable-range evidence instead of reparsing `capture.data`.
- `Image` has explicit `Layout.File` or `Layout.Mapped` storage. Construct file images from bytes with `pe.Image(data)`; use `pe.Image.from_mapped(data, load_base)` for independently acquired mapped bytes.
- `image.headers.preferred_base` is the header value; `image.load_base` is the actual mapped address. Checked `read(rva, size)` uses the declared layout and rejects missing data or virtual-only file tails.
- `to_mapped()` lays out file sections and zero-fills virtual tails. `to_file()` produces file-shaped bytes from captured sections; it does not rebuild imports. Missing section contents prevent conversion, while unreadable alignment gaps can be harmless.

Images and feature views share immutable backing. Editors create independent local state.

## Inspect Features

| Access | Purpose |
|---|---|
| `image.headers`, `image.sections` | Header values, directories, and section layout |
| `image.imports`, `image.imports.delay`, `image.imports.bound` | Import declarations, IAT discovery, delay recovery, and bound-dependency checks |
| `image.exports` | Export table, aliases, ordinals, and forwarders |
| `image.resources` | Typed resource paths and payload ranges |
| `image.relocations`, `image.tls` | Relocation records and candidates; TLS directory and callbacks |
| `image.load_config`, `image.exceptions`, `image.clr`, `image.debug` | Metadata and bounded structural checks |
| `image.security` | Certificate metadata and file-only overlay information |
| `image.code` | Static API-reference scans and bounded tracing for supported x86/x64/ARM64 patterns |
| `image.inspect()`, `image.embedded_images()` | Aggregate metadata/anomalies and embedded PE candidates |

Feature views retain layout, address, and capture context. Directory checks distinguish absent, valid, invalid, unsupported, and file-only data. PE constants live in `br3k.pe`; memory constants and protection helpers live in `br3k.mem`.

## Compare Memory And Disk

```python
comparison = view.compare(capture)
for change in comparison.exports.changes():
    print(change.names, hex(change.rva), change.before.hex(), change.after.hex())
for diagnostic in comparison.diagnostics:
    print(diagnostic.stage.name, diagnostic.message)
```

One comparison shares relocation normalization and section matching across section, byte-range, export-entry, IAT, and resource checks. Components run on demand; export-entry changes group aliases by RVA and retain raw reference bytes alongside normalized evidence.

Offline inputs use `pe.analysis.Comparison(captured_image, reference_file_image)`. Machine, timestamp, and SizeOfImage must match. `comparison.complete` covers the shared context, not optional checks that have not run. Inspect component errors, diagnostics, and truncation flags before interpreting an empty result as clean.

## Recover And Review

```python
plan = view.recover(capture)
for issue in plan.validate():
    print(issue.severity.name, issue.kind.name, hex(issue.rva))
result = plan.build()
print(result.status.name)
br3k.fs.write_bytes("recovered.dll", result.image.data)
```

The default `recovery.Strength.Auto` combines IAT discovery, bounded code analysis, and surviving import declarations. `Fast` reduces tracing; `Aggressive` broadens discovery. `recovery.Options` provides explicit overrides.

`plan.model` is editable and uses the target's pointer width. Validation and building use its current revision against the original input. Evidence and diagnostics remain available on the plan. Offline recovery uses `pe.recovery.analyze(image, symbols, reference=reference_image)`.

Partial output requires `allow_partial=True`. Default resource preservation only fills an absent directory from a matching reference. Relocation inference is a separate opt-in and makes the result partial. `BuildStatus.Complete` describes reconstruction checks, not guaranteed loader compatibility or execution.

## Edit Explicitly

```python
editor = image.to_file().edit()
editor.headers.sanitize()
editor.tls.clear_callbacks()
result = editor.build()
```

Feature editors cover headers, imports/delay imports, resources, relocations, and TLS. They share one local image and revision; failed operations preserve both. File-structure rebuilding requires file layout, while TLS clearing and rebasing support both layouts. A build preserves its editor's layout.

## Hidden Images And Process Evidence

```python
scan = view.scan()
for candidate in scan.hidden_candidates:
    capture = view.capture(candidate)
    plan = view.recover(capture)
    print(candidate.score, plan.synthetic_headers, plan.header_prefix)
```

Scanning combines executable allocation layout, surviving PE artifacts, mapped-file paths, page protections, working-set evidence, and thread start/stack context. Scores rank candidates; they do not prove a hidden DLL.

Recovery consumes the selected capture. When headers are missing, surviving sections or memory-region protections can produce a synthetic analysis image while preserving captured virtual addresses. Architecture comes from target evidence, not the host. Missing section bytes are not invented, and unknown entry points remain zero.

## Limits

- Code analysis recognizes bounded patterns, not arbitrary obfuscation or universal hook destinations. Changed bytes and heuristic scores are evidence to investigate, not security verdicts.
- Directory validation is structural. Exception checks are not an unwinder; CLR checks are not managed-code verification. Specialized hybrid/dynamic-relocation/enclave/volatile/hotpatch metadata, unknown versions, x86 exception directories, and file-offset-only debug payloads may remain `Unsupported`.
- Certificates and overlays are file-only. Memory captures cannot recreate an absent overlay or a valid signature. Synthetic images and partial builds may be useful for analysis without being runnable.

For API details, configure the editor's stub path to `stubs` or use the [generated reference](api/pe/index.md). Documentation generation and runtime docstring limitations are described in the [generator guide](../tools/python-api/README.md).
