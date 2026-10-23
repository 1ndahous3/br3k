# =============================================================================
# IMPORTANT USAGE NOTICE
# 1. Use only for authorized, non-malicious education, research, and testing.
# =============================================================================

# Scenario: compare loaded process modules with their disk images. The report
# lists modules, prints PE directory/section information for each selected module,
# compares changed exported prologues and IAT slots.
#
# Config globals: PROCESS_NAME / PROCESS_ID, MODULE_NAME.

import br3k

PROCESS_NAME = globals().get("PROCESS_NAME", "notepad.exe")
PROCESS_ID = globals().get("PROCESS_ID", None)
MODULE_NAME = globals().get("MODULE_NAME", None)


def open_process(process_name, process_id):
    args = {
        "process_open_strategy": br3k.proc.ProcessOpenStrategy.OpenProcess,
        "process_vm_read_strategy": br3k.proc.ProcessVmReadStrategy.ReadVirtualMemory,
    }
    if process_id is None:
        process = br3k.proc.Process(name=process_name, **args)
    else:
        process = br3k.proc.Process(pid=str(process_id), **args)

    process.open()
    process.init_memory()
    return process


def selected_modules(modules, module_name):
    if module_name is None or module_name == "":
        if len(modules) == 0:
            raise RuntimeError("The target process has no loaded modules")

        return modules

    module_name = module_name.lower()
    selected = []

    for module in modules:
        base_name = module.BaseDllName.lower()
        full_name = module.FullDllName.lower()

        if base_name == module_name or full_name.endswith("\\" + module_name):
            selected.append(module)

    if len(selected) == 0:
        raise RuntimeError(f"Module is not loaded: {module_name}")

    return selected


def bytes_hex(data):
    return " ".join(f"{byte:02x}" for byte in data)


def bytes_sample_text(data, truncated):
    text = bytes_hex(data)
    if truncated:
        text += " ..."

    return text


def hash_text(value):
    if value is None:
        return "unavailable"

    return hex(value)


def enum_text(value):
    if hasattr(value, "name"):
        return value.name

    return str(value)


def import_target_text(module_name, name, ordinal):
    if name is not None:
        return f"{module_name}!{name}"
    if ordinal is not None:
        return f"{module_name}!#{ordinal}"

    return f"{module_name}!<unknown>"


def resolved_address_text(module_name, name, ordinal, address):
    if module_name is None:
        return hex(address)

    return f"{import_target_text(module_name, name, ordinal)}@{hex(address)}"


def image_has_data_directory(image, index):
    try:
        return not image.headers.directory(index).empty
    except Exception:
        return False


def append_report_line(lines, line, emit=None):
    lines.append(line)
    if emit is not None:
        emit(line)


def append_report_lines(lines, source_lines, emit=None):
    for line in source_lines:
        append_report_line(lines, line, emit)


def data_directory_lines(image, title):
    lines = [f"{title}:"]
    any_directory = False

    for index, name in enumerate(br3k.pe.PE_DATA_DIRECTORY_NAMES):
        try:
            directory = image.headers.directory(index)
        except Exception as exc:
            lines.append(f"  {name}: unavailable ({exc})")
            continue

        if directory.empty:
            continue

        any_directory = True
        lines.append(f"  {name}: rva={hex(directory.virtual_address)} size={hex(directory.size)}")

    if not any_directory:
        lines.append("  none")

    return lines


def resource_info_line(info):
    return (
        f"rva={hex(info.virtual_address)} size={hex(info.size)} "
        f"dirs={info.directory_count} named={info.named_entry_count} ids={info.id_entry_count} "
        f"data_entries={info.data_entry_count} data_size={info.data_size} depth={info.max_depth}"
    )


def directory_info_line(info):
    if not info.present:
        return "none"

    return f"rva={hex(info.rva)} size={hex(info.size)}"


def optional_hex(value):
    if value is None:
        return "none"

    return hex(value)


def load_config_line(load_config):
    if not load_config.present:
        return "none"

    features = []
    if load_config.guard_cf_instrumented:
        features.append("CFG")
    if load_config.guard_cf_function_table_present:
        features.append("CFG-table")
    if load_config.guard_rf_enabled:
        features.append("RF")
    if load_config.has_xfg:
        features.append("XFG")
    if load_config.has_cast_guard:
        features.append("CastGuard")
    if load_config.has_guard_memcpy:
        features.append("GuardMemcpy")
    if load_config.has_chpe_metadata:
        features.append("CHPE/ARM64X")
    if load_config.has_dynamic_value_relocations:
        features.append("dynamic-reloc")
    if load_config.has_hotpatch_table:
        features.append("hotpatch")
    if load_config.has_enclave_config:
        features.append("enclave")
    if load_config.has_volatile_metadata:
        features.append("volatile")
    if load_config.has_guard_eh_continuations:
        features.append("guard-eh")

    text = f"{directory_info_line(load_config)} structure_size={optional_hex(load_config.structure_size)}"
    if load_config.guard_flags is not None:
        text += f" guard_flags={hex(load_config.guard_flags)}"
    if len(load_config.guard_flag_names) != 0:
        text += " flags=[" + ", ".join(load_config.guard_flag_names) + "]"
    if len(features) != 0:
        text += " features=[" + ", ".join(features) + "]"

    return text


def bound_check_lines(check, indent="    "):
    source = "none" if check.dependency_source is None else enum_text(check.dependency_source)
    text = (
        f"{indent}{check.dll_name}: {enum_text(check.kind)} {enum_text(check.status)} "
        f"expected={optional_hex(check.expected_timestamp)} actual={optional_hex(check.dependency_timestamp)} "
        f"source={source} dependencies_match={check.matches_dependencies()}"
    )
    if check.reserved is not None and check.reserved != 0:
        text += f" reserved={hex(check.reserved)}"
    lines = [text]
    for forwarder in check.forwarders:
        lines.extend(bound_check_lines(forwarder, indent + "  "))
    return lines


def metadata_lines(title, image, export_map=None):
    try:
        metadata = image.inspect()
    except Exception as exc:
        return [f"{title}: unavailable ({exc})"]

    lines = [f"{title}:"]
    security = metadata.security
    if security.present:
        lines.append(f"  security: file_offset={hex(security.file_offset)} size={hex(security.size)}")
    else:
        lines.append("  security: none")

    rich = metadata.rich_header
    if rich.present:
        lines.append(f"  rich_header: offset={hex(rich.offset)} size={hex(rich.size)} hash={hex(rich.hash)}")
    else:
        lines.append("  rich_header: none")

    lines.append(f"  load_config: {load_config_line(metadata.load_config)}")
    lines.append(f"  base_relocations: {directory_info_line(metadata.base_relocations)}")

    tls = metadata.tls
    callbacks = "" if len(tls.callbacks) == 0 else " callbacks=" + ", ".join(hex(callback) for callback in tls.callbacks)
    lines.append(f"  tls: {directory_info_line(tls)}{callbacks}")
    lines.append(f"  delay_imports: {directory_info_line(metadata.delay_imports)}")
    lines.append(f"  bound_imports: {directory_info_line(metadata.bound_imports)}")
    if metadata.bound_imports.present:
        try:
            descriptors = image.imports.bound.entries()
            for descriptor in descriptors:
                lines.append(f"    {descriptor.dll_name}: timestamp={hex(descriptor.time_date_stamp)} rva={hex(descriptor.descriptor_rva)}")
                for forwarder in descriptor.forwarders:
                    lines.append(f"      forwarder {forwarder.dll_name}: timestamp={hex(forwarder.time_date_stamp)} reserved={hex(forwarder.reserved)}")
        except Exception as exc:
            lines.append(f"    unavailable ({exc})")
    if export_map is not None:
        try:
            checks = image.imports.bound.check(export_map)
            if checks:
                lines.append("  bound_dependency_checks:")
                for check in checks:
                    lines.extend(bound_check_lines(check))
        except Exception as exc:
            lines.append(f"  bound_dependency_checks: unavailable ({exc})")
    lines.append(f"  dotnet: {directory_info_line(metadata.dotnet)}")

    if len(metadata.packer_hints) != 0:
        lines.append("  packer_hints:")
        for hint in metadata.packer_hints:
            lines.append(f"    {hint.name}: {hint.reason}")
    if len(metadata.anomalies) != 0:
        lines.append("  anomalies:")
        for anomaly in metadata.anomalies:
            lines.append(f"    {anomaly.summary()}")

    return lines

def compare_module(view, module):
    print(f"\n{'=' * 78}\n{module.BaseDllName}: base={hex(module.DllBase)} size={hex(module.SizeOfImage)}")
    capture = view.capture(module)
    print(f"  source={capture.path} captured_complete={capture.complete}")
    for gap in capture.missing:
        print(f"  missing rva={hex(gap.rva)} size={hex(gap.size)}: {gap.message}")
    image = capture.image()
    for line in data_directory_lines(image, "directories"):
        print(line)
    print("sections:")
    for section in image.sections:
        print(f"  {section.name}: rva={hex(section.virtual_address)} size={hex(section.size())} characteristics={hex(section.characteristics)}")
    for line in metadata_lines("mapped_metadata", image):
        print(line)
    comparison = view.compare(capture)
    for line in metadata_lines("disk_metadata", comparison.reference):
        print(line)
    print("section_comparison: relocation normalization and runtime-directory masking")
    for section in comparison.sections.sections:
        if section.mapped_error or section.disk_error:
            print(f"  {section.name}: unavailable ({section.mapped_error or section.disk_error})")
        else:
            print(f"  {section.name}: {'changed' if section.changed else 'equal'}")
    for diagnostic in comparison.diagnostics:
        print(f"  {diagnostic.stage.name}: {diagnostic.message}")
    try:
        print("export_entry_changes:")
        for change in comparison.exports.changes():
            print(f"  {', '.join(change.names)}: rva={hex(change.rva)} section={change.section}")
            print(f"    mapped: {bytes_hex(change.after)}")
            print(f"    disk:   {bytes_hex(change.before)}")
            if change.raw_before != change.before:
                print(f"    raw:    {bytes_hex(change.raw_before)}")
    except Exception as exc:
        print(f"export_entry_changes: unavailable ({exc})")
    try:
        changes = comparison.bytes.changes()
        print(f"byte_changes: {changes.changed_byte_count}; ranges={changes.range_count}; truncated={changes.truncated}")
        for change in changes.ranges:
            print(f"  {change.section_name}: rva={hex(change.rva)} size={hex(change.size)}")
    except Exception as exc:
        print(f"byte_changes: unavailable ({exc})")
    try:
        changes = comparison.resources.changes()
        print(f"resource_changes: {len(changes)}")
        for change in changes:
            path = "/".join(entry.text for entry in change.path)
            print(f"  {change.kind.name}: {path}")
    except Exception as exc:
        print(f"resource_changes: unavailable ({exc})")
    try:
        print("import_addresses: resolving expected targets")
        report = comparison.imports.changes(view.symbols)
        for change in report.changes:
            print(f"  {change.module_name}!{change.name or change.ordinal}: iat={hex(change.iat_rva)} expected={hex(change.expected_address)} actual={hex(change.actual_address)}")
        for diagnostic in report.diagnostics:
            print(f"  {diagnostic.stage.name}: {diagnostic.message}")
        for failure in view.source_errors:
            print(f"  source {failure.name}: {failure.message}")
    except Exception as exc:
        print(f"import_addresses: unavailable ({exc})")


if __name__ == "__main__":
    print("Script: PE memory/disk comparison")
    br3k.sysapi.init()
    view = br3k.pe.ProcessView(open_process(PROCESS_NAME, PROCESS_ID))
    print("process_loaded_modules:")
    for module in view.modules:
        print(f"  {hex(module.DllBase)} {module.BaseDllName} size={hex(module.SizeOfImage)} path={module.FullDllName}")
    for module in selected_modules(view.modules, MODULE_NAME):
        try:
            compare_module(view, module)
        except Exception as exc:
            print(f"  module_error: {exc}")
