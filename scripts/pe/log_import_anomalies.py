# =============================================================================
# IMPORTANT USAGE NOTICE
# 1. Use only for authorized, non-malicious education, research, and testing.
# =============================================================================

# Analyze import declarations, resolved addresses, and recovery evidence.
# No image is modified or written. Edit the module selection for a narrower
# experiment; unresolved sources and failed modules remain visible.

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
    print("Script: Import anomalies")
    br3k.sysapi.init()
    view = br3k.pe.ProcessView(open_process())
    for module in view.modules:
        print(f"{module.BaseDllName}: {hex(module.DllBase)}")
        try:
            plan = view.recover(view.capture(module))
            print(f"  recovered={plan.recovered}; delay={plan.delay_imports.status.name}")
            for diagnostic in plan.diagnostics:
                print(f"  {diagnostic.stage.name}: {diagnostic.message}")
            if plan.declaration_error is not None:
                print(f"  declarations: {plan.declaration_error}")
            for issue in plan.validate():
                print(f"  {issue.severity.name} {issue.kind.name}: {issue.module_name} rva={hex(issue.rva)}")
        except Exception as exc:
            print(f"  unavailable: {exc}")
    for failure in view.source_errors:
        print(f"Symbol source {failure.name}: {failure.message}")
