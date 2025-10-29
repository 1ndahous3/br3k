# br3k

**br3k** is a mini-framework for Windows pentesting, designed to implement non-standard scenarios and combine interesting methods.

### Usage

The tool consists of two parts:
1. **Core**: a `.exe`/`.dll` binary with low-level code and a built-in Python interpreter (runtime provides the `br3k` module).
2. **Scripts**: python3 scripts that leverage the `br3k` module API to implement logic.

---

## Scripts

Example scripts can be found in the `scripts` directory, demonstrating well-known techniques.

#### Injection

| Aliases | Script | Description (Short) | References |
|---|---|---|---|
| Thread execution hijacking | `inject_hijack_remote_thread.py` | Open process (WX) → Open thread → Suspend thread → Write code → Resume thread | [IRED Team](https://www.ired.team/offensive-security/code-injection-process-injection/injecting-to-remote-process-via-thread-hijacking) |
| Create thread injection | `inject_create_remote_thread.py` | Open process (WX) → (optional) Write executable code → Create thread | [IRED Team](https://www.ired.team/offensive-security/code-injection-process-injection/process-injection) |
| Process hollowing | `inject_create_process_hollow.cpp` | Create suspended process → Write new image (fixing VAs) → Unmap original image → Configure (PEB, Thread EP) → Resume thread | [IRED Team](https://www.ired.team/offensive-security/code-injection-process-injection/process-hollowing-and-pe-image-relocations) |
| Process doppelgänging | `inject_create_process_doppel.py` | Create NTFS transaction → Write malicious image → (transacted) Write original image → Create executable section → Rollback transaction → Create process w/o thread → Create thread on executable section | [Black Hat](https://www.blackhat.com/docs/eu-17/materials/eu-17-Liberman-Lost-In-Transaction-Process-Doppelganging.pdf), [IRED Team](https://www.ired.team/offensive-security/code-injection-process-injection/process-doppelganging) |
| `IRundown::DoCallback()` injection | `inject_com_irundown_docallback.py` | Open process (RX) → Read COM secrets in process memory → Execute code via `IRundown::DoCallback()` COM method | [MDSec](https://www.mdsec.co.uk/2022/04/process-injection-via-component-object-model-com-irundowndocallback/) |
| APC injection | `inject_queue_apc.py` | Open process (WX) → (optional) Write executable code → Open specified/found alertable thread → Queue user APC | [IRED Team](https://www.ired.team/offensive-security/code-injection-process-injection/early-bird-apc-queue-code-injection) |
| EarlyBird APC injection | `inject_queue_apc_early_bird.py` | Create suspended process → Write executable code → Queue user APC in main thread → Resume main thread | [CyberBit](https://www.cyberbit.com/endpoint-security/new-early-bird-code-injection-technique-discovered/), [IRED Team](https://www.ired.team/offensive-security/code-injection-process-injection/early-bird-apc-queue-code-injection) |

---

## Core

The core implements unique concepts and techniques to enhance the tool's utility.

#### System modules

Features:
- Resolve functions and global structures of the image (retrieve RVA/offsets from PDB symbols).
- Locate RWX data caves in the `.data` section (up to the end of the page).
- Search for ROP gadgets in the `.text` section.

#### NT API

Most system APIs are called directly from **ntdll.dll**, bypassing **kernel32.dll**/**user32.dll** wrappers.

Options:
- Load a clean copy of **ntdll.dll** to avoid hooked functions.
- **[TODO]** Use direct syscalls (bypassing hooks).
- Leverage alternative APIs (e.g., `NtCreateProcess()`, `NtMapViewOfSectionEx()`), which are rarely used.

#### RPC API

By default, the core uses standard COM/RPC wrappers, but deeper options exist (avoiding hooks).

Options:
- Use RPC interfaces (including undocumented ones) via IDL-generated code.
- **[TODO]** Call functions from RPC client libraries (**winspool.drv**, etc.).
- **[TODO]** Use `NdrClientCallX()` with raw RPC structs.
- **[TODO]** Make direct ALPC calls.

#### Remote process read/write

Besides the usual scenario of allocating and writing to executable memory, there are some more interesting ones:
- Creating a shared section and mapping it into a remote process (to obtain a remote address).
- Creating a shared section and mapping it into both remote and local processes (for read/write via local address).

For read-only scenarios, the tool can create a live system dump (`NtSystemDebugControl(SysDbgGetLiveKernelDump, ...)`) and parse any process's memory.

#### Remote process execution flow and ROP gadgets

Sometimes it's possible to force remote process to call some function (to change IP), but it is not possible to pass arguments.
In some scenarios it can be bypassed via special ROP gadgets in system DLLs: they place the first args into registers (according to `__fastcall`) and jump to the address of the desired function.

Using of it requires manual stack preparation:
- Place function args (≤4) + function address (for the ROP gadget).
- Place function args (>4) + shadow space + return address (for the function itself).

There are two cases, depending on what process data and what registers can be changed:
1. If it is possible to write RW data, then construct and write our part of the stack:
   - Set IP to the address of the ROP gadget.
   - Set SP to the address of the new stack (only if we do not write data to the current stack, but create a new one).
2. If it is possible to write WX code, then construct a shellcode that will construct (push on) the stack and call the ROP gadget.
   - Set IP to the address of the shellcode.

The core provides APIs to simplify stack/shellcode construction for both cases.

#### Other features

- Since the core part is built as an EXE/DLL with IPC protocol, it is possible to implement complex scenarios with chained execution of scripts in several processes (e.g., one script can send another to be executed via the br3k DLL in the context of another process).
- **[TODO]** Execute commands in separate threads (bypassing thread-correlation detections).

---

## Notes

### Why Rust

Originally prototyped in [C/C++](https://github.com/1ndahous3/br3k/tree/cpp), this project was later rewritten in Rust because:
- Cargo provides many libraries, avoiding git submodules or copying header-only helpers.
- `build.rs` allows flexible code generation and custom build logic without CMake hacks and external scripts.
- [RustPython](https://github.com/RustPython/RustPython) allows easy embedding of Python VM (unlike [CPython](https://github.com/python/cpython), which is extremely hard to statically compile with frozen stdlib modules).
- Rust reflection simplifies generating code for various structs.

The project uses unsafe code extensively, so Rust is chosen for convenience and tooling rather than memory safety.

### Acknowledgments

- [Process Hacker (phnt)](https://github.com/processhacker/phnt)
- [Mimikatz](https://github.com/gentilkiwi/mimikatz)
- [Hasherezade's repositories](https://github.com/hasherezade?tab=repositories)
- [Awesome Injection](https://github.com/itaymigdal/awesome-injection)
