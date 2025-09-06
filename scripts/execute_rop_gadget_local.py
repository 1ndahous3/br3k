import br3k
from br3k import ProcessOpenMethod, ProcessMemoryStrategy

if __name__ == "__main__":
    print("Script: Execute shellcode locally (via ROP gadget)")
    print()

    br3k.init_sysapi(ntdll_copy=True)

    process = br3k.Process(
        name="br3k-cli.exe",
        memory_strategy=ProcessMemoryStrategy.AllocateInAddr,
        open_method=ProcessOpenMethod.OpenProcess
    )

    process.open()
    process.init_memory()

    pfn_messagebox = br3k.get_proc_address("user32.dll", "MessageBoxW")
    br3k.shellcode_write_exec_via_rop_gadget(process, ep=pfn_messagebox)

    ep = process.get_memory_remote_address()
    br3k.shellcode_execute(ep)

    br3k.script_success()
