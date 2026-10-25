# =============================================================================
# IMPORTANT USAGE NOTICE
# 1. Use only for authorized, non-malicious education, research, and testing.
# 2. This script is part of the test suite. It requires the config globals declared in the header;
#    pass every required value explicitly (for example, with the CLI '--config' option),
#    using `null` when a value is intentionally unset.
# 3. For standalone use with your own targets, it's more convenient to replace the globals
#    with concrete values and keep only the logic you need.
# =============================================================================

# Preserve original IAT slot identities through recovery and file round trips.
PROCESS_ID: int = globals()["PROCESS_ID"]
MODULE_NAME: str | None = globals()["MODULE_NAME"]
OUTPUT_PATH: str = globals()["OUTPUT_PATH"]

import br3k


def open_process(process_id: int) -> br3k.proc.Process:
    process = br3k.proc.Process(pid=str(process_id),
        process_open_strategy=br3k.proc.ProcessOpenStrategy.OpenProcess,
        process_vm_read_strategy=br3k.proc.ProcessVmReadStrategy.ReadVirtualMemory)
    process.open()
    process.init_memory()
    return process


def select_module(view: br3k.pe.ProcessView, name: str | None) -> br3k.proc.Module:
    if name is None:
        return view.modules[0]
    return next(module for module in view.modules if module.BaseDllName.lower() == name.lower())


def check_recovery(view: br3k.pe.ProcessView, module: br3k.proc.Module) -> None:
    capture = view.capture(module)
    plan = view.recover(capture)
    assert isinstance(plan, br3k.pe.recovery.Plan)
    assert plan.model is plan.model
    expected = {
        item.rva: (item.module_name.lower(), item.name, None if item.name else item.ordinal)
        for item in plan.model.imports() if item.valid
    }
    assert expected, "fixture/system DLL did not exercise IAT recovery"
    result = plan.build(allow_partial=True, discover_relocations=True)
    actual = {}
    for descriptor in result.image.imports.entries():
        assert descriptor.dll_name is not None
        for item in descriptor.imports:
            actual[item.import_address_table_rva] = (descriptor.dll_name.lower(), item.name, item.ordinal)
    for rva, identity in expected.items():
        assert actual.get(rva) == identity, f"IAT slot moved or changed at {hex(rva)}: {identity} -> {actual.get(rva)}"
    output = OUTPUT_PATH
    br3k.fs.write_bytes(output, result.image.data)
    reloaded = br3k.pe.Image.from_file(br3k.fs.read_bytes(output))
    assert len(reloaded.imports.entries()) == len(result.image.imports.entries())
    print(f"  {module.BaseDllName}: preserved_slots={len(expected)} status={result.status.name}")
    for diagnostic in result.diagnostics:
        print(f"  diagnostic: {diagnostic.stage.name}: {diagnostic.message}")


if __name__ == "__main__":
    br3k.sysapi.init()
    view = br3k.pe.ProcessView(open_process(PROCESS_ID))
    check_recovery(view, select_module(view, MODULE_NAME))
