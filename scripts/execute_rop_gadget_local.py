import br3k
from br3k import ProcessOpenStrategy, ProcessVmStrategy

BR3K_CLI_PROCESS_NAME = "br3k-cli.exe"

if __name__ == "__main__":
    print("Script: Execute shellcode locally (via ROP gadget)")
    print()

    br3k.init_sysapi()

    process = br3k.Process(
        name=BR3K_CLI_PROCESS_NAME,
        memory_strategy=ProcessVmStrategy.AllocateInAddr,
        process_open_strategy=ProcessOpenStrategy.OpenProcess
    )

    process.open()
    process.init_memory()

    pfn_messagebox = br3k.get_proc_address("user32.dll", "MessageBoxW")
    br3k.shellcode_write_exec_via_rop_gadget(process, ep=pfn_messagebox)

    ep = process.get_memory_remote_address()
    br3k.shellcode_execute(ep)

    br3k.script_success()
