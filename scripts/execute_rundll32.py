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
    ipc = br3k.Ipc(process)
    ipc.create()

    script_data = br3k.FileMapping(SCRIPT_FILEPATH)
    ipc.send_data(script_data.bytes())

    br3k.script_success()
