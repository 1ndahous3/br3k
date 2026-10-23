# =============================================================================
# IMPORTANT USAGE NOTICE
# 1. Use only for authorized, non-malicious education, research, and testing.
# =============================================================================

import br3k
from br3k import ProcessOpenStrategy, ProcessVmWriteStrategy

PROCESS_NAME = "notepad.exe"

INJECT_DLL = True # otherwise shellcode
DLL_PATH = b"path\\to\\br3k_dll.dll"
SCRIPT_FILEPATH = "path\\to\\script.py"

if __name__ == "__main__":

    print("Script: Inject via NtCreateThread()")
    print()

    br3k.init_sysapi()

    if INJECT_DLL:
        write_data = DLL_PATH
    else:
        write_data = br3k.shellcode_get_messageboxw()

    process = br3k.Process(
        name=PROCESS_NAME,
        process_vm_write_strategy=ProcessVmWriteStrategy.AllocateInAddr,
        process_open_strategy=ProcessOpenStrategy.OpenProcess
    )

    process.open()
    process.init_memory()
    process.create_memory(size=len(write_data))
    process.write_memory(data=write_data)

    thread = br3k.Thread(process)

    if INJECT_DLL:
        arg = process.get_memory_remote_address()
        ep = br3k.get_proc_address("kernel32.dll", "LoadLibraryA")
        thread.create(ep=ep, arg=arg)

        br3k_ipc = br3k.Br3kIPC(process)
        br3k_ipc.create()

        script_data = br3k.FileMapping(SCRIPT_FILEPATH)
        br3k_ipc.send_data(script_data.bytes())
    else:
        ep = process.get_memory_remote_address()
        thread.create(ep=ep)
