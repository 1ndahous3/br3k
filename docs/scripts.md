# Scripts

Example scripts can be found in the `scripts` directory. This collection contains only examples of some well-known techniques and does not cover all the capabilities of the framework. They provide small, editable starting points for experiments.

Test-oriented scenarios live in `tests/vm/` and run inside the br3k VM with explicit config globals, for example through the CLI `--config` option. Config files are YAML documents with a top-level `variables` object. `--config` can be repeated; later config files override earlier values.

## Layout

| Directory | Purpose |
|---|---|
| `scripts/pe/`, `scripts/inject/`, `scripts/ipc/`, `scripts/proc/`, `scripts/shellcode/` | Compact, editable user scenarios, executed inside the br3k VM. |
| `tests/vm/` | Feature-level br3k scenarios grouped by subsystem, with example configs next to the scripts. |
| `tests/host/` | Rust integration tests that run the CLI and manage process fixtures. |
| `tests/fixtures/` | Cargo package for native test fixtures. |
| `target/test-runs/` | Isolated case directories; failed cases retain configs, dumps, and logs. Not committed. |

See [Testing](https://github.com/1ndahous3/br3k/blob/main/tests/README.md) for build and test commands.

## Injection

| Aliases | Script | Description | References |
|---|---|---|---|
| Thread execution hijacking | `scripts/inject/hijack_remote_thread.py` | Open process (WX) -> open thread -> suspend thread -> write code -> resume thread | [IRED Team](https://www.ired.team/offensive-security/code-injection-process-injection/injecting-to-remote-process-via-thread-hijacking) |
| Create thread injection | `scripts/inject/create_remote_thread.py` | Open process (WX) -> optionally write executable code -> create thread | [IRED Team](https://www.ired.team/offensive-security/code-injection-process-injection/process-injection) |
| Process hollowing | `scripts/inject/create_process_hollow.py` | Create suspended process -> write new image and fix VAs -> configure PEB/thread EP -> resume thread | [IRED Team](https://www.ired.team/offensive-security/code-injection-process-injection/process-hollowing-and-pe-image-relocations) |
| Process doppelganging | `scripts/inject/create_process_doppel.py` | Create NTFS transaction -> write image -> create executable section -> rollback transaction -> create process/thread from the section | [Black Hat](https://www.blackhat.com/docs/eu-17/materials/eu-17-Liberman-Lost-In-Transaction-Process-Doppelganging.pdf), [IRED Team](https://www.ired.team/offensive-security/code-injection-process-injection/process-doppelganging) |
| `IRundown::DoCallback()` injection | `scripts/inject/com_irundown_docallback.py` | Open process (RX) -> read COM state from process memory -> execute code through `IRundown::DoCallback()` | [MDSec](https://www.mdsec.co.uk/2022/04/process-injection-via-component-object-model-com-irundowndocallback/) |
| APC injection | `scripts/inject/queue_apc.py` | Open process (WX) -> optionally write executable code -> open or find alertable thread -> queue user APC | [IRED Team](https://www.ired.team/offensive-security/code-injection-process-injection/early-bird-apc-queue-code-injection) |
| Early Bird APC injection | `scripts/inject/queue_apc_early_bird.py` | Create suspended process -> write executable code -> queue user APC in main thread -> resume main thread | [CyberBit](https://www.cyberbit.com/endpoint-security/new-early-bird-code-injection-technique-discovered/), [IRED Team](https://www.ired.team/offensive-security/code-injection-process-injection/early-bird-apc-queue-code-injection) |
| Thread pool work item injection | `scripts/inject/thread_pool.py` | Open process (WX) -> write executable code -> queue a thread-pool work item | [PoolParty](https://github.com/SafeBreach-Labs/PoolParty) |

## Other Scripts

- `scripts/proc/log_handles.py`: logs open handles in the process.
- `scripts/pe/recover_module.py`: captures one live module, recovers imports, preserves resources or restores them from a matching reference, optionally infers missing relocations, sanitizes headers, and writes output with an explicit complete/partial status.
- `scripts/pe/recover_unpacked_process.py`: scans for a hidden/unpacked PE candidate and recovers the first strong candidate; if none is found, recovers the main loaded module. The recovery flow also adds discovered relocations when the table is missing.
- `scripts/pe/log_import_anomalies.py`: recovers imports without writing an image and emits a researcher log with invalid imports, suspicious ranges, duplicate thunks, and code references.
- `scripts/pe/compare_memory_disk.py`: incrementally compares loaded modules with disk references, reporting directories/sections, resource payload differences, bound-import metadata, IAT changes, and modified executable export entries grouped by RVA aliases. Read and normalization failures remain visible.
- `scripts/pe/find_hidden_modules.py`: scans executable memory outside the PEB module list, reports hidden or manually mapped PE candidates, and can dump/recover all reported candidates in the same run.
- `scripts/pe/scan_process_anomalies.py`: prints a compact memory IOC report with loaded modules, suspicious executable regions, executable working-set private-page evidence, thread-start/thread-stack diagnostics, and typed hidden-module scan findings.
- `scripts/pe/dump_process_modules.py`: dumps every loaded module as a file-shaped PE image, optionally keeping only modules whose mapped bytes differ from disk.
- `scripts/pe/generate_pe_baseline.py`: records normalized header hashes and export-prologue hashes for loaded module files on a known-good host.
- `scripts/pe/trace_api_references.py`: traces bounded entry-point references to loaded exports without rebuilding the image. The image's code view also supports full-image scans for specialized scenarios. See [PE analysis and recovery](pe_recovery.md).
- `scripts/ipc/execute_br3k_cli.py`: executes br3k CLI and passes another script through br3k IPC.
- `scripts/ipc/execute_br3k_dll_rundll32.py`: executes `rundll32.exe` with the br3k DLL and passes another script through br3k IPC.
- `scripts/shellcode/execute_rop_gadget_local.py`: executes local code through ROP-gadget helpers.

## Tests

- `tests/vm/pe/image.py`: checks PE capture, typed views, layout conversion, and comparisons.
- `tests/vm/pe/editing.py`: checks local editing and source immutability.
- `tests/vm/pe/recovery.py`: checks IAT preservation and recovered-file round trips.
- `tests/vm/pe/scan.py`: checks process memory and thread diagnostics.
- `tests/vm/pe/trace.py`: checks bounded code-reference tracing.
- `tests/vm/pe/capture_lifetime.py`: checks capture ownership and generation rules.
- `tests/vm/pe/validate_file.py`: validates PE files emitted by scenarios.
- `tests/vm/inject/code.py`: iterates code injection and execution scenarios.
- `tests/vm/inject/images.py`: iterates image injection and substitution scenarios.
- `tests/vm/fs/operations.py`: iterates file open, delete, and change scenarios.
