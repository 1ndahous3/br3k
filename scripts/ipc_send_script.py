import br3k
from br3k import ProcessVmStrategy

BR3K_CLI_FILEPATH = "path\\to\\br3k-cli.exe"
SCRIPT_FILEPATH = "path\\to\\script.py"

if __name__ == "__main__":

    print("Script: create new instance of CLI and send another script via IPC")
    print()

    br3k.init_sysapi()

    process = br3k.Process(
        image_path=BR3K_CLI_FILEPATH,
        memory_strategy=ProcessVmStrategy.AllocateInAddr
    )

    process.create_user(suspended=True)
    process.init_memory()

    ipc = br3k.Ipc(process)
    ipc.create()
    process.resume_thread()

    script_data = br3k.FileMapping(SCRIPT_FILEPATH)
    ipc.send_data(script_data.bytes())

    br3k.script_success()
