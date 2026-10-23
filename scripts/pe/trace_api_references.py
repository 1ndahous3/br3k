# =============================================================================
# IMPORTANT USAGE NOTICE
# 1. Use only for authorized, non-malicious education, research, and testing.
# =============================================================================

# Trace bounded control flow from the selected image's entry point and report
# API references. This is code analysis, not import reconstruction or execution.
# The native engine selects x86/x64/ARM64 decoding from the captured image.

import br3k

PROCESS_NAME = globals().get("PROCESS_NAME", "notepad.exe")
PROCESS_ID = globals().get("PROCESS_ID", None)


def open_process():
    target = {"name": PROCESS_NAME} if PROCESS_ID is None else {"pid": str(PROCESS_ID)}
    process = br3k.proc.Process(
        **target,
        process_open_strategy=br3k.proc.ProcessOpenStrategy.OpenProcess,
        process_vm_read_strategy=br3k.proc.ProcessVmReadStrategy.ReadVirtualMemory,
    )
    process.open()
    process.init_memory()
    return process

MODULE_NAME = globals().get("MODULE_NAME", None)


if __name__ == "__main__":
    print("Script: API reference tracing")
    br3k.sysapi.init()
    view = br3k.pe.ProcessView(open_process())
    module = view.modules[0] if MODULE_NAME is None else next(
        module for module in view.modules if module.BaseDllName.lower() == MODULE_NAME.lower()
    )
    image = view.capture(module).image()
    print(f"{module.BaseDllName}: entry_point={hex(image.headers.entry_point)}")
    trace = image.code.trace(image.headers.entry_point, view.symbols, max_blocks=64, max_bytes=0x4000)
    print(f"Trace: blocks={trace.visited_blocks} bytes={trace.scanned_bytes}")
    for reference in trace.references:
        name = reference.name if reference.name is not None else f"#{reference.ordinal}"
        print(f"  rva={hex(reference.reference_rva)} {reference.kind.name}: {reference.module_name}!{name}")
    for failure in view.source_errors:
        print(f"Symbol source {failure.name}: {failure.message}")
