# =============================================================================
# IMPORTANT USAGE NOTICE
# 1. Use only for authorized, non-malicious education, research, and testing.
# 2. This script is part of the test suite. It requires the config globals declared in the header;
#    pass every required value explicitly (for example, with the CLI '--config' option),
#    using `null` when a value is intentionally unset.
# 3. For standalone use with your own targets, it's more convenient to replace the globals
#    with concrete values and keep only the logic you need.
# =============================================================================

# Editing a local image copy must not mutate its source.
PROCESS_ID = PROCESS_ID
MODULE_NAME = MODULE_NAME

import br3k


def open_process(process_id):
    process = br3k.proc.Process(pid=str(process_id),
        process_open_strategy=br3k.proc.ProcessOpenStrategy.OpenProcess,
        process_vm_read_strategy=br3k.proc.ProcessVmReadStrategy.ReadVirtualMemory)
    process.open()
    process.init_memory()
    return process


def select_module(view, name):
    if name is None:
        return view.modules[0]
    return next(module for module in view.modules if module.BaseDllName.lower() == name.lower())


if __name__ == "__main__":
    br3k.sysapi.init()
    view = br3k.pe.ProcessView(open_process(PROCESS_ID))
    reference = view.reference(select_module(view, MODULE_NAME))
    source = reference.data
    editor = reference.edit()
    before = editor.revision
    editor.headers.sanitize()
    assert editor.revision > before
    editor.tls.clear_callbacks()
    result = editor.build()
    assert isinstance(result, br3k.pe.BuildResult)
    assert reference.data == source, "editor mutated its source"
    assert result.image.layout is br3k.pe.Layout.File
    assert result.image.headers.machine == reference.headers.machine
    assert len(result.image.sections) == len(reference.sections)
    assert result.image.read(0, 2) == b"MZ"
    assert isinstance(result.image.imports.entries(), list)
