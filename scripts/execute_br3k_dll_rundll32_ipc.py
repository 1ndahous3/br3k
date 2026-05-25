# =============================================================================
# IMPORTANT USAGE NOTICE
# 1. Use only for authorized, non-malicious education, research, and testing.
# =============================================================================

import subprocess
import br3k

PROCESS_IMAGE = "C:\\Windows\\System32\\rundll32.exe"
DLL_PATH = "path\\to\\br3k_dll.dll"
SCRIPT_FILEPATH = "path\\to\\script.py"

if __name__ == "__main__":

    print("Script: Execute rundll32 with DLL")
    print()

    br3k.init_sysapi()

    subprocess.Popen([PROCESS_IMAGE, DLL_PATH, "DllMain"], shell=True, stdin=None, stdout=None, stderr=None, close_fds=True)

    process = br3k.Process(name="rundll32.exe")
    br3k_ipc = br3k.Br3kIPC(process)
    br3k_ipc.create()

    script_data = br3k.FileMapping(SCRIPT_FILEPATH)
    br3k_ipc.send_data(script_data.bytes())
