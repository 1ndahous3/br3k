# =============================================================================
# IMPORTANT USAGE NOTICE
# 1. Use only for authorized, non-malicious education, research, and testing.
# 2. This script is part of the test suite. It requires the config globals declared in the header;
#    pass every required value explicitly (for example, with the CLI '--config' option),
#    using `null` when a value is intentionally unset.
# 3. For standalone use with your own targets, it's more convenient to replace the globals
#    with concrete values and keep only the logic you need.
# =============================================================================

# Captures belong to one view generation but keep their captured bytes alive.
PROCESS_ID = PROCESS_ID

import br3k


def open_process(process_id):
    process = br3k.proc.Process(pid=str(process_id),
        process_open_strategy=br3k.proc.ProcessOpenStrategy.OpenProcess,
        process_vm_read_strategy=br3k.proc.ProcessVmReadStrategy.ReadVirtualMemory)
    process.open()
    process.init_memory()
    return process


def expect_error(error_type, operation):
    try:
        operation()
    except error_type:
        return
    raise AssertionError(f"expected {error_type.__name__}")


def check_generation(view, process, module):
    capture = view.capture(module)
    other = br3k.pe.ProcessView(process)
    expect_error(ValueError, lambda: other.compare(capture))
    generation = view.generation
    view.refresh()
    assert view.generation == generation + 1
    expect_error(ValueError, lambda: view.recover(capture))
    assert capture.image().read(0, 2) == b"MZ"


if __name__ == "__main__":
    br3k.sysapi.init()
    process = open_process(PROCESS_ID)
    view = br3k.pe.ProcessView(process)
    check_generation(view, process, view.modules[0])
