# =============================================================================
# IMPORTANT USAGE NOTICE
# 1. Use only for authorized, non-malicious education, research, and testing.
# 2. This script is part of the test suite. It requires the config globals declared in the header;
#    pass every required value explicitly (for example, with the CLI '--config' option),
#    using `null` when a value is intentionally unset.
# 3. For standalone use with your own targets, it's more convenient to replace the globals
#    with concrete values and keep only the logic you need.
# =============================================================================

# Bound code-reference traversal by explicit byte/block limits.
PROCESS_ID = PROCESS_ID

import br3k


def open_process(process_id):
    process = br3k.proc.Process(pid=str(process_id),
        process_open_strategy=br3k.proc.ProcessOpenStrategy.OpenProcess,
        process_vm_read_strategy=br3k.proc.ProcessVmReadStrategy.ReadVirtualMemory)
    process.open()
    process.init_memory()
    return process


def check_trace(view, module):
    image = view.capture(module).image()
    trace = image.code.trace(image.headers.entry_point, view.symbols, max_blocks=16, max_bytes=4096)
    assert isinstance(trace, br3k.pe.code.Trace)
    assert trace.visited_blocks <= 16 and trace.scanned_bytes <= 4096
    assert all(isinstance(item, br3k.pe.code.Reference) for item in trace.references)
    print(f"  blocks={trace.visited_blocks} bytes={trace.scanned_bytes} references={len(trace.references)}")


if __name__ == "__main__":
    br3k.sysapi.init()
    view = br3k.pe.ProcessView(open_process(PROCESS_ID))
    check_trace(view, view.modules[0])
