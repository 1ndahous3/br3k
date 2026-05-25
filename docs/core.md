# Core

The full set of operations and feature configuration flags can be found in the `.pyi` stub (TODO) or in the `tests` suite scripts.

## Python module and core features

The `br3k` Python module provides the API implemented by the framework core. It exposes primitives for working with various objects:

- Files
- Processes
- Threads
- PE/PDB metadata
- COM/RPC helpers

```python
process = br3k.Process(
    name="notepad.exe",
    process_open_strategy=br3k.ProcessOpenStrategy.OpenProcess,
)

process.open()
```

### System API

Most system APIs are called directly from the NT API (`ntdll`), bypassing Win32 `kernel32` and `user32` wrappers.

**br3k** lets scripts select API strategies: how to open a target process, read/write its memory, suspend or resume it, and so on.

```python
process = br3k.Process(
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
br3k.init_sysapi(
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
mapped = br3k.FileMapping(r"C:\Windows\System32\ntdll.dll")
pe = br3k.Pe(mapped.data, mapped.size, True)

pdb_path = br3k.pdb_download(pe, br3k.fs_get_temp_folder())
pdb = br3k.Pdb(pdb_path)

rtl_user_thread_rva = pdb.get_symbol_rva("RtlCreateUserThread")
teb_peb_offset = pdb.get_field_offset("_TEB", "ProcessEnvironmentBlock")
```

The module can also work with data and code in system DLLs:

Locate RW data caves in the `.data` section (up to the end of the page).

```python
cave = br3k.rw_cave()
```

Search for ROP gadgets in the `.text` section.

```python
inf_loop = br3k.gadget_inf_loop()
```

### br3k IPC

Since the core is built as an EXE/DLL with the simple IPC protocol, complex scenarios can chain scripts across several processes.

For example, one script can send another script to be executed by the **br3k** DLL in a remote process context.

```python
process = br3k.Process(image_path=r"C:\path\to\br3k-cli.exe")
process.create_user(suspended=True)

br3k_ipc = br3k.Br3kIPC(process)
br3k_ipc.create()

process.main_thread.resume()

script_data = br3k.FileMapping(r"C:\path\to\next_script.py")
br3k_ipc.send_data(script_data.bytes())
```

### Remote Process ROP Gadgets

Sometimes it is possible to force a remote process to call a function by changing IP, but not possible to pass arguments directly.
In some scenarios this can be bypassed with special ROP gadgets in system DLLs: the gadgets place the first arguments into registers according to `__fastcall` and then jump to the desired function.

The core provides APIs to simplify stack and shellcode construction for those cases.

```python
pfn_messageboxw = br3k.get_proc_address("user32.dll", "MessageBoxW")
br3k.shellcode_write_exec_via_rop_gadget(
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
