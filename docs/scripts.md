# Scripts

Example scripts can be found in the `scripts` directory. They demonstrate known techniques and provide small, editable starting points for experiments.

Test-oriented scenarios live in the `tests` directory and are intended to be launched with explicit config globals, for example through the CLI `--config` option.

## Injection

| Aliases | Script | Description | References |
|---|---|---|---|
| Thread execution hijacking | `scripts/inject_hijack_remote_thread.py` | Open process (WX) -> open thread -> suspend thread -> write code -> resume thread | [IRED Team](https://www.ired.team/offensive-security/code-injection-process-injection/injecting-to-remote-process-via-thread-hijacking) |
| Create thread injection | `scripts/inject_create_remote_thread.py` | Open process (WX) -> optionally write executable code -> create thread | [IRED Team](https://www.ired.team/offensive-security/code-injection-process-injection/process-injection) |
| Process hollowing | `scripts/inject_create_process_hollow.py` | Create suspended process -> write new image and fix VAs -> configure PEB/thread EP -> resume thread | [IRED Team](https://www.ired.team/offensive-security/code-injection-process-injection/process-hollowing-and-pe-image-relocations) |
| Process doppelganging | `scripts/inject_create_process_doppel.py` | Create NTFS transaction -> write image -> create executable section -> rollback transaction -> create process/thread from the section | [Black Hat](https://www.blackhat.com/docs/eu-17/materials/eu-17-Liberman-Lost-In-Transaction-Process-Doppelganging.pdf), [IRED Team](https://www.ired.team/offensive-security/code-injection-process-injection/process-doppelganging) |
| `IRundown::DoCallback()` injection | `scripts/inject_com_irundown_docallback.py` | Open process (RX) -> read COM state from process memory -> execute code through `IRundown::DoCallback()` | [MDSec](https://www.mdsec.co.uk/2022/04/process-injection-via-component-object-model-com-irundowndocallback/) |
| APC injection | `scripts/inject_queue_apc.py` | Open process (WX) -> optionally write executable code -> open or find alertable thread -> queue user APC | [IRED Team](https://www.ired.team/offensive-security/code-injection-process-injection/early-bird-apc-queue-code-injection) |
| Early Bird APC injection | `scripts/inject_queue_apc_early_bird.py` | Create suspended process -> write executable code -> queue user APC in main thread -> resume main thread | [CyberBit](https://www.cyberbit.com/endpoint-security/new-early-bird-code-injection-technique-discovered/), [IRED Team](https://www.ired.team/offensive-security/code-injection-process-injection/early-bird-apc-queue-code-injection) |

## Other Scripts
- `scripts/log_handles.py`: logs open handles in the process.
- `scripts/execute_br3k_cli_ipc.py`: executes br3k CLI and passes another script through br3k IPC.
- `scripts/execute_br3k_dll_rundll32_ipc.py`: executes `rundll32.exe` with the br3k DLL and passes another script through br3k IPC.
- `scripts/execute_rop_gadget_local.py`: executes local code through ROP-gadget helpers.

## Tests

- `tests/injects_code.py`: iterates code injection and execution scenarios.
- `tests/injects_images.py`: iterates image injection and substitution scenarios.
