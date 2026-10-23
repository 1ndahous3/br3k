# =============================================================================
# IMPORTANT USAGE NOTICE
# 1. Use only for authorized, non-malicious education, research, and testing.
# =============================================================================

# Scenario: generate a clean-ish baseline from currently loaded module files:
# normalized header hashes plus per-export prologue hashes. Use it on a known
# good host, then compare future live reports against the recorded values.
#
# Config globals: PROCESS_NAME / PROCESS_ID.

import br3k

PROCESS_NAME = globals().get("PROCESS_NAME", "notepad.exe")
PROCESS_ID = globals().get("PROCESS_ID", None)


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


def quote_yaml(value):
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


def baseline_for_module(view, module):
    if module.FullDllName is None or module.FullDllName == "":
        return [
            f"- name: {quote_yaml(module.BaseDllName)}",
            f"  base: {quote_yaml(hex(module.DllBase))}",
            "  error: \"module path is empty\"",
        ]

    try:
        image = view.reference(module)
        data = image.data
        header_hash = br3k.pe.headers.normalized_hash(data)
    except Exception as exc:
        return [
            f"- name: {quote_yaml(module.BaseDllName)}",
            f"  path: {quote_yaml(module.FullDllName)}",
            f"  error: {quote_yaml(exc)}",
        ]

    prologue_error = None
    try:
        if image.headers.directory(br3k.pe.PE_DIRECTORY_ENTRY_EXPORT).empty:
            prologues = []
        else:
            prologues = br3k.pe.exports.prologue_hashes(
                data,
                image_base=module.DllBase,
                module_name=module.BaseDllName,
                prologue_size=16,
            )
    except Exception as exc:
        prologues = []
        prologue_error = str(exc)

    lines = [
        f"- name: {quote_yaml(module.BaseDllName)}",
        f"  path: {quote_yaml(module.FullDllName)}",
        f"  base: {quote_yaml(hex(module.DllBase))}",
        f"  size: {quote_yaml(hex(module.SizeOfImage))}",
        f"  normalized_header_hash: {quote_yaml(hex(header_hash))}",
        "  export_prologues:",
    ]
    if prologue_error is not None:
        lines.append(f"    error: {quote_yaml(prologue_error)}")
    elif len(prologues) == 0:
        lines.append("    []")
    else:
        for item in prologues:
            lines.append(f"    - rva: {quote_yaml(hex(item.rva))}")
            lines.append(f"      hash: {quote_yaml(hex(item.hash))}")
            lines.append(f"      size: {item.size}")
            lines.append("      names:")
            for name in item.names:
                lines.append(f"        - {quote_yaml(name)}")

    return lines


if __name__ == "__main__":
    print("Script: PE baseline generation")

    br3k.sysapi.init()

    process = open_process(PROCESS_NAME, PROCESS_ID)
    view = br3k.pe.ProcessView(process)
    modules = view.modules
    output_file = "pe_baseline.yaml"
    # Avoid retaining every module's string objects in the x86 VM.
    output = bytearray(b"modules:\n")

    print(f"loaded_modules: {len(modules)}")
    for index, module in enumerate(modules):
        print(f"module {index + 1}/{len(modules)}: {module.BaseDllName}")
        output.extend(("\n".join(baseline_for_module(view, module)) + "\n").encode())

    br3k.fs.write_bytes(output_file, bytes(output))
    print(f"baseline_file: {output_file}")
