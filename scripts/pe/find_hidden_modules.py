# =============================================================================
# IMPORTANT USAGE NOTICE
# 1. Use only for authorized, non-malicious education, research, and testing.
# =============================================================================

# Find executable allocations missing from the loader's module list.
# Recovery uses the selected captured allocation without scanning again.
# Headerless output is an analysis image, not a reconstructed original program.
# Set RECOVER_HIDDEN_CANDIDATES to True to write all reported candidates.

from typing import Any

import br3k

PROCESS_NAME: str = globals().get("PROCESS_NAME", "notepad.exe")
PROCESS_ID: int | None = globals().get("PROCESS_ID", None)
RECOVER_HIDDEN_CANDIDATES: bool = globals().get("RECOVER_HIDDEN_CANDIDATES", False)


def enum_text(value):
    if hasattr(value, "name"):
        return value.name

    return str(value)


def open_process(process_name: str, process_id: int | None) -> br3k.proc.Process:
    args: dict[str, Any] = {
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


def region_line(region: br3k.proc.MemoryRegion) -> str:
    line = (
        f"{hex(region.BaseAddress)}-{hex(region.EndAddress)} "
        f"size={hex(region.RegionSize)} state={br3k.mem.state_text(region.State)} "
        f"protect={br3k.mem.protection_text(region.Protect)} type={br3k.mem.type_text(region.Type)}"
    )
    if region.MappedPath is not None:
        line += f" mapped_path={region.MappedPath}"

    return line


def candidate_report_lines(candidate: br3k.pe.analysis.HiddenModuleCandidate, index: int) -> list[str]:
    regions = candidate.regions
    span = candidate.span()
    types = sorted(set(br3k.mem.type_text(region.Type) for region in regions))
    protections = sorted(set(br3k.mem.protection_text(region.Protect) for region in regions))
    lines = [
        f"candidate {index}: allocation_base={hex(candidate.allocation_base)} score={candidate.score}",
        f"  span: {hex(span.start)}-{hex(span.end)} size={hex(span.size)} regions={len(regions)}",
        f"  types: {', '.join(types)}",
        f"  protections: {', '.join(protections)}",
        "  reasons:",
    ]

    for reason in candidate.reasons:
        lines.append(f"    - {reason.text()}")

    lines.append("  region_layout:")
    for region in regions:
        lines.append(f"    {region_line(region)}")

    if len(candidate.read_errors) != 0:
        lines.append("  read_errors:")
        for error in candidate.read_errors:
            lines.append(f"    {error}")

    lines.append("  pe_artifacts:")
    if len(candidate.artifacts) == 0:
        lines.append("    none")
    else:
        for artifact in candidate.artifacts:
            details = [
                f"{enum_text(artifact.kind)}@{hex(artifact.address)}",
                f"alloc+{hex(artifact.offset)}",
                f"score={artifact.score}",
                f"sections={artifact.section_count}",
                f"covered_sections={artifact.coverage_count}",
            ]
            if artifact.machine is not None:
                details.append(f"machine={artifact.machine}")
                details.append(f"dll={artifact.is_dll}")
            if artifact.e_lfanew is not None:
                details.append(f"e_lfanew={hex(artifact.e_lfanew)}")
            if artifact.section_table_offset is not None:
                details.append(f"section_table=alloc+{hex(artifact.section_table_offset)}")

            lines.append(f"    {' '.join(details)}")
            lines.append(f"      {artifact.section_summary()}")

    return lines


if __name__ == "__main__":
    print("Script: PE hidden module scan")
    br3k.sysapi.init()
    view = br3k.pe.ProcessView(open_process(PROCESS_NAME, PROCESS_ID))
    scan = view.scan()
    print("loaded_modules:")
    for module in view.modules:
        print(f"  {hex(module.DllBase)} {module.BaseDllName} size={hex(module.SizeOfImage)}")
    candidates = scan.hidden_candidates
    print(f"hidden_candidates: {len(candidates)}")
    for index, candidate in enumerate(candidates, 1):
        for line in candidate_report_lines(candidate, index):
            print(line)
        if not RECOVER_HIDDEN_CANDIDATES:
            continue
        try:
            capture = view.capture(candidate)
            for gap in capture.missing:
                print(f"  missing rva={hex(gap.rva)} size={hex(gap.size)}: {gap.message}")
            plan = view.recover(capture)
            print(f"  synthetic_headers={plan.synthetic_headers} header_prefix={hex(plan.header_prefix)}")
            for issue in plan.validate():
                print(f"  {issue.severity.name} {issue.kind.name}: {issue.module_name} rva={hex(issue.rva)}")
            result = plan.build(allow_partial=True, discover_relocations=True)
            for diagnostic in result.diagnostics:
                print(f"  {diagnostic.stage.name}: {diagnostic.message}")
            output = f"recovered_hidden_{candidate.allocation_base:x}.dll"
            br3k.fs.write_bytes(output, result.image.data)
            print(f"  output={output}; status={result.status.name}")
        except Exception as exc:
            print(f"  recovery_failed: {exc}")
