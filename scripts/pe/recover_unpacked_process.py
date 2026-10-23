# =============================================================================
# IMPORTANT USAGE NOTICE
# 1. Use only for authorized, non-malicious education, research, and testing.
# =============================================================================

# Capture the first strong hidden/unpacked candidate, or the main loaded image.
# Run at the point your experiment considers ready, or move this block into
# your own deterministic scenario. This script does not guess an original
# entry point, wait for a packer, or execute the reconstructed output.

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

if __name__ == "__main__":
    print("Script: Recover unpacked process")
    br3k.sysapi.init()
    view = br3k.pe.ProcessView(open_process())
    scan = view.scan()
    candidates = scan.hidden_candidates
    print(f"Hidden candidates: {len(candidates)}")
    if candidates:
        target = candidates[0]
        print(f"Selected hidden candidate: {hex(target.allocation_base)}; score={target.score}")
    else:
        if not view.modules:
            raise RuntimeError("The target has no loaded modules")
        target = view.modules[0]
        print(f"Selected main image: {target.BaseDllName} at {hex(target.DllBase)}")
    capture = view.capture(target)
    options = br3k.pe.recovery.Options(strength=br3k.pe.recovery.Strength.Auto)
    print(f"Import recovery: {options.strength.name}")
    plan = view.recover(capture, options=options)
    for issue in plan.validate():
        print(f"  {issue.severity.name} {issue.kind.name}: {issue.module_name} rva={hex(issue.rva)}")
    result = plan.build(allow_partial=True, discover_relocations=True)
    for diagnostic in result.diagnostics:
        print(f"  {diagnostic.stage.name}: {diagnostic.message}")
    output = f"unpacked_{capture.name}"
    if not output.lower().endswith((".exe", ".dll")):
        output += ".dll"
    br3k.fs.write_bytes(output, result.image.data)
    print(f"Output: {output}; status={result.status.name}")
