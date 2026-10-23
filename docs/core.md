# Core

PE workflows are described in [PE analysis and recovery](pe_recovery.md). The [Python API reference](api/index.md) and [editor stubs](../stubs/br3k/__init__.pyi) cover every registered namespace and are generated from Rust declarations and doc comments with `cargo api`. The `tests` suite scripts cover framework strategies and configuration flags.

## Python module and core features

The `br3k` Python module provides the API implemented by the framework core. It exposes primitives for working with various objects:

- Files
- Processes
- Threads
- PE/PDB metadata
- COM/RPC helpers

New scripts should prefer namespaced helpers such as `br3k.proc`, `br3k.fs`, `br3k.pe`, `br3k.pdb`, `br3k.com`, `br3k.ipc`, `br3k.shellcode`, and `br3k.sysapi`. Older non-PE top-level names remain available; PE workflows use the canonical namespaced API.

```python
process = br3k.proc.Process(
    name="notepad.exe",
    process_open_strategy=br3k.ProcessOpenStrategy.OpenProcess,
)

process.open()
```

Process memory layout can be enumerated from Python. `Process.memory_map()` returns a typed map with all regions, committed regions, executable regions, and allocation-base grouping. The region records expose raw `NtQueryVirtualMemory` fields and helper flags, which is useful for deterministic scans over image, mapped, and private executable memory.

```python
process = br3k.proc.Process(
    name="notepad.exe",
    process_open_strategy=br3k.ProcessOpenStrategy.OpenProcess,
    process_vm_read_strategy=br3k.ProcessVmReadStrategy.ReadVirtualMemory,
)
process.open()
process.init_memory()

memory_map = process.memory_map()

for region in memory_map.executable:
    if region.IsCommitted and region.IsExecutable:
        print(hex(region.BaseAddress), hex(region.RegionSize), hex(region.Protect), hex(region.Type))
```

Thread start addresses and stack bounds can also be collected through the NT process snapshot path. `br3k.pe.ProcessView(process).scan()` classifies starts against loaded modules and memory regions, while `Process.threads()` exposes the raw thread records.

```python
for thread in process.threads():
    print(thread.ThreadId, hex(thread.StartAddress), thread.StackLimit, thread.StackBase)
```

PE diagnostics are exposed through `br3k.pe` so scripts can compare live mapped images with disk files, inspect PE metadata, hash normalized headers, and build export-prologue baselines without doing raw binary parsing in Python.

```python
view = br3k.pe.ProcessView(process)
capture = view.capture(view.modules[0])
comparison = view.compare(capture)
metadata = capture.image().inspect()
header_hash = br3k.pe.headers.normalized_hash(comparison.reference.data)
```

`Capture` retains unreadable ranges; `Image` retains explicit file/mapped layout. Feature views group imports, resources, TLS, relocations, and other metadata. Recovery uses `view.recover(capture)` and a source-bound plan; local modifications use `image.edit()`. Both return a `BuildResult` whose status must be checked before using its output.

### System API

Most system APIs are called directly from the NT API (`ntdll`), bypassing Win32 `kernel32` and `user32` wrappers.

**br3k** lets scripts select API strategies: how to open a target process, read/write its memory, suspend or resume it, and so on.

```python
process = br3k.proc.Process(
    name="notepad.exe",
    process_open_strategy=br3k.ProcessOpenStrategy.OpenProcess,
    process_vm_read_strategy=br3k.ProcessVmReadStrategy.ReadVirtualMemory,
    process_vm_write_strategy=br3k.ProcessVmWriteStrategy.CreateSectionMap,
    thread_open_strategy=br3k.ThreadOpenStrategy.ThreadOpenAnyNext,
)
```

It is also possible to:

- Choose the system API backend: use system DLLs (default), clean DLL copies, or direct syscalls.
- Use a specific variant from a set of similar low-level functions, such as `NtAllocateVirtualMemory` or `NtAllocateVirtualMemoryEx`.

```python
br3k.sysapi.init(
    sys_api_backend="DirectSyscall",
    sys_api_dispatch={
        "CreateThread": "NtCreateThreadEx",
        "AllocateVirtualMemory": "NtAllocateVirtualMemoryEx",
        "QueueApcThread": "NtQueueApcThreadEx",
        "SetInformation_Delete": "FileDispositionInformationEx",
    },
)
```

### System Modules

**br3k** can resolve functions and global structures of an image by retrieving RVAs and offsets from PDB symbols.

```python
mapped = br3k.fs.FileMapping(r"C:\Windows\System32\ntdll.dll")
pe = br3k.pe.native.PtrImage(mapped.data, mapped.size, True)

pdb_path = br3k.pdb.download(pe, br3k.fs.get_temp_folder())
pdb = br3k.pdb.Pdb(pdb_path)

rtl_user_thread_rva = pdb.get_symbol_rva("RtlCreateUserThread")
teb_peb_offset = pdb.get_field_offset("_TEB", "ProcessEnvironmentBlock")
```

The module can also work with data and code in system DLLs:

Locate RW data caves in the `.data` section (up to the end of the page).

```python
cave = br3k.shellcode.rw_cave()
```

Search for ROP gadgets in the `.text` section.

```python
inf_loop = br3k.shellcode.gadget_inf_loop()
```

### br3k IPC

Since the core is built as an EXE/DLL with the simple IPC protocol, complex scenarios can chain scripts across several processes.

For example, one script can send another script to be executed by the **br3k** DLL in a remote process context.

```python
process = br3k.proc.Process(image_path=r"C:\path\to\br3k-cli.exe")
process.create_user(suspended=True)

br3k_ipc = br3k.ipc.Br3kIPC(process)
br3k_ipc.create()

process.main_thread.resume()

script_data = br3k.fs.FileMapping(r"C:\path\to\next_script.py")
br3k_ipc.send_data(script_data.bytes())
```

### Remote Process ROP Gadgets

Sometimes it is possible to force a remote process to call a function by changing IP, but not possible to pass arguments directly. In some scenarios this can be bypassed with special ROP gadgets in system DLLs: the gadgets place the first arguments into registers according to `__fastcall` and then jump to the desired function.

The core provides APIs to simplify stack and shellcode construction for those cases.

```python
pfn_messageboxw = br3k.sysapi.get_proc_address("user32.dll", "MessageBoxW")
br3k.shellcode.write_exec_via_rop_gadget(
    process,
    ep=pfn_messageboxw,
    args=[0, 0, 0, 0],
)

[...]

thread.set_ep(new_thread=False, ep=process.get_memory_remote_address())
thread.resume()
```

### RPC API

**br3k** internally uses standard COM/RPC wrappers through system client DLLs, but deeper options exist for avoiding higher-level wrappers.

Some interfaces are undocumented by design, so they are integrated through IDL-generated code.

Options (TODO):

- Call functions from RPC client libraries such as `winspool.drv`.
- Use `NdrClientCallX()` with raw RPC structs.
- Make direct ALPC calls.

### Script execution flow (TODO)

For effective testing against defensive software, planned module configuration should allow changing the script execution payload:

- Execute commands in separate threads to bypass thread correlations.
- Execute commands in subprocesses to bypass process correlations.
