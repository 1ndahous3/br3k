# =============================================================================
# IMPORTANT USAGE NOTICE
# 1. Use only for authorized, non-malicious education, research, and testing.
# 2. This script is part of the test suite. It requires the config globals declared in the header;
#    pass every required value explicitly (for example, with the CLI '--config' option),
#    using `null` when a value is intentionally unset.
# 3. For standalone use with your own targets, it's more convenient to replace the globals
#    with concrete values and keep only the logic you need.
# =============================================================================

# Capture, typed PE views, layout conversion, and memory/disk comparisons.
PROCESS_ID: int = globals()["PROCESS_ID"]
MODULE_NAME: str | None = globals()["MODULE_NAME"]

from collections.abc import Callable

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


def expect_error(error_type: type[Exception], operation: Callable[[], object]) -> None:
    try:
        operation()
    except error_type:
        return
    raise AssertionError(f"expected {error_type.__name__}")


def check_image(image: br3k.pe.Image) -> None:
    assert isinstance(image, br3k.pe.Image)
    assert image.headers.pointer_size in (4, 8)
    assert image.headers.image_size > 0
    assert image.sections and image.read(0, 2) == b"MZ"
    assert image.va_to_rva(image.rva_to_va(0x1000)) == 0x1000
    for section in image.sections:
        assert isinstance(section, br3k.pe.headers.Section)
        assert isinstance(section.summary(), str)
    for index in range(len(br3k.pe.PE_DATA_DIRECTORY_NAMES)):
        assert isinstance(image.headers.directory(index), br3k.pe.headers.DataDirectory)
    assert isinstance(image.imports.entries(), list)
    assert isinstance(image.imports.delay.entries(), list)
    assert isinstance(image.imports.bound.entries(), list)
    if image.headers.directory(br3k.pe.PE_DIRECTORY_ENTRY_RESOURCE).empty:
        expect_error(SystemError, image.resources.entries)
    else:
        assert isinstance(image.resources.entries(), list)
    assert isinstance(image.relocations.entries(), list)
    tls = image.tls.directory()
    assert tls is None or isinstance(tls, br3k.pe.tls.Directory)
    for directory in (image.debug, image.load_config, image.exceptions, image.clr):
        assert isinstance(directory.check(), br3k.pe.headers.DirectoryCheck)
    assert isinstance(image.inspect(), br3k.pe.analysis.MetadataSummary)
    expect_error(ValueError, lambda: image.read(image.headers.image_size + 1, 1))


def check_module(view: br3k.pe.ProcessView, module: br3k.proc.Module) -> None:
    capture = view.capture(module)
    assert isinstance(capture, br3k.pe.Capture)
    assert capture.base == module.DllBase and capture.generation == view.generation
    image = capture.image()
    assert image.layout is br3k.pe.Layout.Mapped and image.load_base == capture.base
    check_image(image)
    reference = view.reference(capture)
    assert reference.layout is br3k.pe.Layout.File
    check_image(reference)
    file_image = image.to_file()
    assert file_image.layout is br3k.pe.Layout.File
    mapped = file_image.to_mapped()
    assert mapped.layout is br3k.pe.Layout.Mapped
    assert mapped.headers.machine == image.headers.machine

    comparison = view.compare(capture)
    assert isinstance(comparison, br3k.pe.analysis.Comparison)
    assert len(comparison.sections.sections) == len(image.sections)
    assert isinstance(comparison.exports.changes(), list)
    assert isinstance(comparison.resources.changes(), list)
    assert isinstance(comparison.imports.changes(view.symbols), br3k.pe.analysis.ImportChanges)
    for diagnostic in comparison.diagnostics:
        print(f"  diagnostic: {diagnostic.stage.name}: {diagnostic.message}")


if __name__ == "__main__":
    br3k.sysapi.init()
    view = br3k.pe.ProcessView(open_process(PROCESS_ID))
    check_module(view, select_module(view, MODULE_NAME))
