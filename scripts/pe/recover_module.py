# =============================================================================
# IMPORTANT USAGE NOTICE
# 1. Use only for authorized, non-malicious education, research, and testing.
# =============================================================================

# Recover the main module, or MODULE_NAME, from a live process.
# Imports are analyzed with Auto strength. Resources are preserved and stale
# checksum/security/bound-import fields are cleared by the native recovery plan.
# Partial output is explicitly allowed for research; its status is printed.
# Reconstructed bytes are not a promise of a runnable executable.

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

MODULE_NAME: str | None = globals().get("MODULE_NAME", None)


if __name__ == "__main__":
    print("Script: PE recovery")
    br3k.sysapi.init()
    view = br3k.pe.ProcessView(open_process())
    modules = view.modules
    module = modules[0] if MODULE_NAME is None else next(
        module for module in modules if module.BaseDllName.lower() == MODULE_NAME.lower()
    )
    print(f"Capturing {module.BaseDllName} at {hex(module.DllBase)}")
    capture = view.capture(module)
    for gap in capture.missing:
        print(f"  missing rva={hex(gap.rva)} size={hex(gap.size)}: {gap.message}")
    plan = view.recover(capture)
    print(f"Recovered imports: {plan.recovered}; delay imports: {plan.delay_imports.status.name}")
    for failure in view.source_errors:
        print(f"  symbol source {failure.name}: {failure.message}")
    for issue in plan.validate():
        print(f"  {issue.severity.name} {issue.kind.name} rva={hex(issue.rva)} module={issue.module_name}")
    result = plan.build(allow_partial=True, discover_relocations=True)
    for diagnostic in result.diagnostics:
        print(f"  {diagnostic.stage.name}: {diagnostic.message}")
    for change in result.changes:
        print(f"  applied: {change.kind.name}")
    output = f"recovered_{module.BaseDllName}"
    br3k.fs.write_bytes(output, result.image.data)
    print(f"Output: {output}; status={result.status.name}")
