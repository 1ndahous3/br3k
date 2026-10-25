# =============================================================================
# IMPORTANT USAGE NOTICE
# 1. Use only for authorized, non-malicious education, research, and testing.
# =============================================================================

# Scenario: print a compact process-memory IOC report. The default flow opens a
# process, lists loaded modules, reports suspicious executable memory, checks
# thread starts/stacks, and runs the hidden-module scanner.
#
# Config globals: PROCESS_NAME / PROCESS_ID.

from typing import Any

import br3k

PROCESS_NAME: str = globals().get("PROCESS_NAME", "notepad.exe")
PROCESS_ID: int | None = globals().get("PROCESS_ID", None)


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


def print_loaded_modules(modules: list[br3k.proc.Module]) -> None:
    print(f"loaded_modules: {len(modules)}")
    for module in modules:
        print(f"  {hex(module.DllBase)}-{hex(module.DllBase + module.SizeOfImage)} {module.BaseDllName} {module.FullDllName}")


def print_process_scan(scan: br3k.pe.analysis.ProcessScan) -> None:
    print()
    print("process_scan:")
    print(f"  modules: {scan.module_count}")
    print(f"  memory_regions: {scan.region_count}")
    print(f"  executable_regions: {scan.executable_region_count}")
    print(f"  orphan_executable_regions: {scan.orphan_executable_region_count}")
    print(f"  hidden_candidates: {scan.visible_hidden_candidate_count}")
    print(f"  findings: {scan.finding_count}")
    if scan.thread_error is None:
        print(f"  threads: {scan.thread_count}")
        print(f"  suspicious_thread_starts: {scan.suspicious_thread_start_count}")
        print(f"  suspicious_thread_stack_regions: {scan.suspicious_thread_stack_region_count}")
    else:
        print(f"  thread_error: {scan.thread_error}")
    if scan.working_set_error is None:
        print(f"  working_set_executable_regions: {scan.working_set_region_count}")
        print(f"  working_set_executable_pages: {scan.working_set_valid_page_count}/{scan.working_set_page_count}")
        print(f"  executable_private_pages: {scan.working_set_private_page_count}")
        print(f"  image_executable_private_pages: {scan.image_executable_private_page_count}")
        print(f"  mapped_executable_private_pages: {scan.mapped_executable_private_page_count}")
        print(f"  private_executable_valid_pages: {scan.private_executable_valid_page_count}")
        print(f"  orphan_executable_private_pages: {scan.orphan_executable_private_page_count}")
    else:
        print(f"  working_set_error: {scan.working_set_error}")


def print_scan_findings(findings: list[br3k.pe.analysis.ScanFinding]) -> None:
    print()
    print("scan_findings:")
    if len(findings) == 0:
        print("  none")
        return

    for index, finding in enumerate(findings):
        print(
            f"  finding {index + 1}: kind={finding.kind.name} address={hex(finding.address)} "
            f"size={hex(finding.size)} score={finding.score}"
        )
        print(f"    reason={finding.reason}")
        if finding.region is not None:
            print(f"    region={region_line(finding.region)}")
        if finding.candidate is not None:
            span = finding.candidate.span()
            print(
                f"    candidate_base={hex(finding.candidate.allocation_base)} "
                f"candidate_span={hex(span.start)}-{hex(span.end)}"
            )


def print_working_set_private_regions(scan: br3k.pe.analysis.ProcessScan) -> None:
    print()
    print("working_set_private_executable_regions:")
    if scan.working_set_error is not None:
        print(f"  skipped: {scan.working_set_error}")
        return

    regions = [
        region for region in scan.working_set_regions
        if region.PrivatePageCount != 0 or region.BadPageCount != 0
    ]

    if len(regions) == 0:
        print("  none")
        return

    for region in regions:
        print(
            f"  {hex(region.BaseAddress)}-{hex(region.EndAddress)} "
            f"size={hex(region.RegionSize)} valid={region.ValidPageCount}/{region.PageCount} "
            f"shared={region.SharedPageCount} private={region.PrivatePageCount} "
            f"bad={region.BadPageCount}"
        )
        print(f"    region={region_line(region.Region)}")


def print_thread_start_diagnostics(scan: br3k.pe.analysis.ProcessScan) -> None:
    print()
    print("thread_start_diagnostics:")
    if scan.thread_error is not None:
        print(f"  skipped: {scan.thread_error}")
        return

    suspicious = scan.suspicious_thread_starts
    if len(suspicious) == 0:
        print("  none")
        return

    if len(suspicious) != 0:
        print("  suspicious:")
        for thread in suspicious:
            print(
                f"    tid={thread.thread_id} start={hex(thread.start_address)} "
                f"kind={thread.kind.name} score={thread.score}"
            )
            print(
                f"      system_start={hex(thread.system_start_address)} "
                f"win32_start={hex(thread.win32_start_address) if thread.win32_start_address is not None else 'none'}"
            )
            print(f"      reason={thread.reason}")
            if thread.module is not None:
                print(f"      module={thread.module.BaseDllName} {thread.module.FullDllName}")
            if thread.region is not None:
                print(f"      region={region_line(thread.region)}")

def print_thread_stack_diagnostics(scan: br3k.pe.analysis.ProcessScan) -> None:
    print()
    print("thread_stack_diagnostics:")
    if scan.thread_error is not None:
        print(f"  skipped: {scan.thread_error}")
        return

    suspicious = scan.suspicious_thread_stack_regions
    if len(suspicious) == 0:
        print("  none")
        return

    for stack in suspicious:
        stack_limit = hex(stack.stack_limit) if stack.stack_limit is not None else "none"
        stack_base = hex(stack.stack_base) if stack.stack_base is not None else "none"
        teb = hex(stack.teb_address) if stack.teb_address is not None else "none"

        print(
            f"  tid={stack.thread_id} teb={teb} stack={stack_limit}-{stack_base} "
            f"kind={stack.kind.name} score={stack.score}"
        )
        print(f"    reason={stack.reason}")
        print(f"    region={region_line(stack.region)}")


def print_hidden_candidates(result: br3k.pe.analysis.HiddenModuleScanResult) -> None:
    visible = result.visible_candidates()

    print()
    print("hidden_module_scan:")
    print(f"  memory_regions: {len(result.regions)}")
    print(f"  orphan_executable_regions: {len(result.orphan_executable)}")
    print(f"  candidate_allocations: {len(result.candidate_allocations)}")
    print(f"  visible_candidates: {len(visible)}")

    if len(visible) == 0:
        print("  none")
    else:
        for index, candidate in enumerate(visible):
            span = candidate.span()
            print()
            print(f"  candidate {index + 1}: base={hex(candidate.allocation_base)} score={candidate.score}")
            print(f"    span={hex(span.start)}-{hex(span.end)} size={hex(span.size)}")
            print("    reasons:")
            for reason in candidate.reasons:
                print(f"      - {reason.text()}")
            print("    regions:")
            for region in candidate.regions:
                print(f"      {region_line(region)}")
            print("    artifacts:")
            if len(candidate.artifacts) == 0:
                print("      none")
            else:
                for artifact in candidate.artifacts:
                    print(
                        f"      {artifact.kind.name}@{hex(artifact.address)} "
                        f"score={artifact.score} sections={artifact.section_count} "
                        f"covered={artifact.coverage_count}"
                    )


if __name__ == "__main__":
    print("Script: PE process anomaly scan")

    br3k.sysapi.init()

    process = open_process(PROCESS_NAME, PROCESS_ID)
    scan = br3k.pe.ProcessView(process).scan()

    print_loaded_modules(scan.modules)
    print_process_scan(scan)
    print_scan_findings(scan.findings)
    print_working_set_private_regions(scan)
    print_thread_start_diagnostics(scan)
    print_thread_stack_diagnostics(scan)
    print_hidden_candidates(scan.hidden_modules)
