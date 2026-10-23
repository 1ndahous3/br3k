# =============================================================================
# IMPORTANT USAGE NOTICE
# 1. Use only for authorized, non-malicious education, research, and testing.
# 2. This script is part of the test suite. It requires the config globals declared in the header;
#    pass every required value explicitly (for example, with the CLI '--config' option),
#    using `null` when a value is intentionally unset.
# 3. For standalone use with your own targets, it's more convenient to replace the globals
#    with concrete values and keep only the logic you need.
# =============================================================================

# Validate a scenario's output as a file-layout PE without executing it.
PROCESS_ID = PROCESS_ID
MODULE_NAME = MODULE_NAME
IMAGE_PATH = IMAGE_PATH
REQUIRE_IMPORTS = REQUIRE_IMPORTS

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
    image = br3k.pe.Image.from_file(br3k.fs.read_bytes(IMAGE_PATH))
    assert image.layout is br3k.pe.Layout.File
    if PROCESS_ID is not None:
        view = br3k.pe.ProcessView(open_process(PROCESS_ID))
        reference = view.reference(select_module(view, MODULE_NAME))
        assert image.headers.machine == reference.headers.machine
    assert image.headers.image_size > 0 and image.sections
    assert image.headers.entry_point < image.headers.image_size
    imports = image.imports.entries()
    if REQUIRE_IMPORTS:
        assert imports, "the fixture output must retain imports"
    for descriptor in imports:
        for entry in descriptor.imports:
            assert 0 < entry.import_address_table_rva < image.headers.image_size
    for section in image.sections:
        assert section.virtual_address < image.headers.image_size
