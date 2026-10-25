# =============================================================================
# IMPORTANT USAGE NOTICE
# 1. Use only for authorized, non-malicious education, research, and testing.
# =============================================================================

# Dump loaded modules as file-layout images without import reconstruction.
# ONLY_CHANGED_MODULES selects modules with observed differences from disk.
# Comparison failures are reported, never treated as equality.

from typing import Any

import br3k

PROCESS_NAME: str = globals().get("PROCESS_NAME", "notepad.exe")
PROCESS_ID: int | None = globals().get("PROCESS_ID", None)


def open_process() -> br3k.proc.Process:
    target: dict[str, Any] = {"name": PROCESS_NAME} if PROCESS_ID is None else {"pid": str(PROCESS_ID)}
    process = br3k.proc.Process(
        **target,
        process_open_strategy=br3k.proc.ProcessOpenStrategy.OpenProcess,
        process_vm_read_strategy=br3k.proc.ProcessVmReadStrategy.ReadVirtualMemory,
    )
    process.open()
    process.init_memory()
    return process

ONLY_CHANGED_MODULES: bool = globals().get("ONLY_CHANGED_MODULES", False)


if __name__ == "__main__":
    print("Script: Dump process modules")
    br3k.sysapi.init()
    view = br3k.pe.ProcessView(open_process())
    for module in view.modules:
        print(f"{module.BaseDllName}: {hex(module.DllBase)} size={hex(module.SizeOfImage)}")
        try:
            capture = view.capture(module)
            if ONLY_CHANGED_MODULES:
                comparison = view.compare(capture)
                if not comparison.complete:
                    for diagnostic in comparison.diagnostics:
                        print(f"  comparison diagnostic: {diagnostic}")
                elif comparison.sections.changed_count == 0:
                    continue
            image = capture.image().to_file()
            output = f"dump_{module.BaseDllName}"
            br3k.fs.write_bytes(output, image.data)
            print(f"  output={output}; captured_complete={capture.complete}")
        except Exception as exc:
            print(f"  unavailable: {exc}")
