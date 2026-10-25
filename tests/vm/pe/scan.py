# =============================================================================
# IMPORTANT USAGE NOTICE
# 1. Use only for authorized, non-malicious education, research, and testing.
# 2. This script is part of the test suite. It requires the config globals declared in the header;
#    pass every required value explicitly (for example, with the CLI '--config' option),
#    using `null` when a value is intentionally unset.
# 3. For standalone use with your own targets, it's more convenient to replace the globals
#    with concrete values and keep only the logic you need.
# =============================================================================

# Read-only process queries. This fixture does not require a hidden candidate.
PROCESS_ID: int = globals()["PROCESS_ID"]

import br3k


def open_process(process_id: int) -> br3k.proc.Process:
    process = br3k.proc.Process(pid=str(process_id),
        process_open_strategy=br3k.proc.ProcessOpenStrategy.OpenProcess,
        process_vm_read_strategy=br3k.proc.ProcessVmReadStrategy.ReadVirtualMemory)
    process.open()
    process.init_memory()
    return process


def check_scan(view: br3k.pe.ProcessView) -> None:
    scan = view.scan()
    assert isinstance(scan, br3k.pe.analysis.ProcessScan)
    assert scan.module_count == len(view.modules)
    assert scan.region_count > 0 and scan.executable_region_count > 0
    assert isinstance(scan.hidden_candidates, list)
    if scan.thread_error or scan.working_set_error:
        raise AssertionError(f"incomplete process queries: {scan.thread_error}; {scan.working_set_error}")
    print(f"  regions={scan.region_count} hidden_candidates={len(scan.hidden_candidates)}")
    print("  No hidden candidate is required; this target is not a hidden-module fixture.")


if __name__ == "__main__":
    br3k.sysapi.init()
    view = br3k.pe.ProcessView(open_process(PROCESS_ID))
    check_scan(view)
