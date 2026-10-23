# =============================================================================
# IMPORTANT USAGE NOTICE
# 1. Use only for authorized, non-malicious education, research, and testing.
# =============================================================================

import br3k

PROCESS_IMAGE = "C:\\Windows\\System32\\rundll32.exe"
DLL_PATH = "path\\to\\br3k_dll.dll"
SCRIPT_FILEPATH = "path\\to\\script.py"

if __name__ == "__main__":

    print("Script: Execute rundll32 with DLL")
    print()

    br3k.init_sysapi()

    script_data = br3k.FileMapping(SCRIPT_FILEPATH)
    process = br3k.Process(image_path=PROCESS_IMAGE)
    process.create_user(suspended=True, command_line=f'"{PROCESS_IMAGE}" "{DLL_PATH}",DllMain')
    br3k_ipc = br3k.Br3kIPC(process)
    br3k_ipc.create()
    process.main_thread.resume()
    br3k_ipc.send_data(script_data.bytes())
