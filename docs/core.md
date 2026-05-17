# Core

The core implements low-level Windows concepts and techniques exposed to scripts through the embedded Python VM.

## System Modules

Features:

- Resolve functions and global structures of an image by retrieving RVAs and offsets from PDB symbols.
- Locate RWX data caves in the `.data` section, up to the end of the page.
- Search for ROP gadgets in the `.text` section.

## NT API

Most system APIs are called directly from `ntdll.dll`, bypassing `kernel32.dll` and `user32.dll` wrappers.

Options:

- Select a system API backend: call exports from loaded DLLs (default), load clean DLL copies, or use direct syscall stubs for supported managed system calls.
- Select explicit system API dispatch variants, such as `NtCreateProcess()` or `NtMapViewOfSectionEx()`, when a technique needs a less common API path.

## RPC API

By default, the core uses standard COM/RPC wrappers, but deeper options exist for avoiding higher-level wrappers.

Options:

- Use RPC interfaces, including undocumented ones, via IDL-generated code.
- **TODO**: Call functions from RPC client libraries such as `winspool.drv`.
- **TODO**: Use `NdrClientCallX()` with raw RPC structs.
- **TODO**: Make direct ALPC calls.

## Remote Process Read/Write

Besides the usual scenario of allocating and writing remote virtual memory, br3k supports more specialized process memory strategies:

- Creating a shared section and mapping it into a remote process to obtain a remote address.
- Creating a shared section and mapping it into both remote and local processes for read/write through a local address.

For read-only scenarios, the tool can create a live system dump with `NtSystemDebugControl(SysDbgGetLiveKernelDump, ...)` and parse process memory from it.

## Remote Process Execution Flow And ROP Gadgets

Sometimes it is possible to force a remote process to call a function by changing IP, but not possible to pass arguments directly.
In some scenarios this can be bypassed with special ROP gadgets in system DLLs: the gadgets place the first arguments into registers according to `__fastcall` and then jump to the desired function.

The core provides APIs to simplify stack and shellcode construction for those cases.

## Other Features

- Since the core is built as an EXE/DLL with an IPC protocol, complex scenarios can chain scripts across several processes. For example, one script can send another script to be executed by the br3k DLL in a remote process context.
- **TODO**: Execute commands in separate threads to bypass thread-correlation detections.
