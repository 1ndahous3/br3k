# =============================================================================
# IMPORTANT USAGE NOTICE
# 1. Use only for authorized, non-malicious education, research, and testing.
# =============================================================================

import br3k
from br3k import ProcessVmWriteStrategy

BR3K_CLI_FILEPATH = "path\\to\\br3k-cli.exe"
SCRIPT_FILEPATH = "path\\to\\script.py"

if __name__ == "__main__":

    print("Script: create new instance of CLI and send another script via IPC")
    print()

    br3k.init_sysapi()

    process = br3k.Process(
        image_path=BR3K_CLI_FILEPATH,
        process_vm_write_strategy=ProcessVmWriteStrategy.AllocateInAddr
    )

    process.create_user(suspended=True)
    process.init_memory()

    br3k_ipc = br3k.Br3kIPC(process)
    br3k_ipc.create()

    thread = process.main_thread
    thread.resume()

    script_data = br3k.FileMapping(SCRIPT_FILEPATH)
    br3k_ipc.send_data(script_data.bytes())
