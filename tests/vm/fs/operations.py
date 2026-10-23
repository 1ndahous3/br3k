# =============================================================================
# IMPORTANT USAGE NOTICE
# 1. Use only for authorized, non-malicious education, research, and testing.
# 2. This script is part of the test suite. It requires the config globals declared in the header;
#    pass every required value explicitly (for example, with the CLI '--config' option),
#    using `null` when a value is intentionally unset.
# 3. For standalone use with your own targets, it's more convenient to replace the globals
#    with concrete values and keep only the logic you need.
# =============================================================================

# globals (config)
TARGET_FILE = TARGET_FILE

# script
from enum import IntEnum

import br3k
from br3k import FileChangeStrategy, FileDeleteStrategy, FileOpenStrategy, FsFileMode

TEST_DATA = b"br3k-file-suite-data"

SYS_API_DISPATCH_ALTERNATIVE = {
    "CreateSection": "NtCreateSectionEx",
    "MapViewOfSection": "NtMapViewOfSectionEx",
    "UnmapViewOfSection": "NtUnmapViewOfSectionEx",
    "SetInformation_Delete": "FileDispositionInformationEx",
}

SYS_API_BACKEND_CASES = (
    "Dll",
    "DirectSyscall",
)

SYS_API_DISPATCH_CASES = (
    ("default", None),
    ("alternative", SYS_API_DISPATCH_ALTERNATIVE),
)

class FileTestType(IntEnum):
    OpenFile = 1
    DeleteFile = 2
    ChangeDeleteFile = 3
    ChangeOpenFile = 4
    ChangeCreateFileMapping = 5

def enum_items(enum_type):
    return [
        value
        for value in enum_type
    ]

def enum_case_name(value):
    return value.name if value is not None else None

def init_sysapi(sys_api_backend, sys_api_dispatch):
    if sys_api_dispatch is None:
        br3k.init_sysapi(sys_api_backend=sys_api_backend)
    else:
        br3k.init_sysapi(sys_api_backend=sys_api_backend, sys_api_dispatch=sys_api_dispatch)

def delete_target_if_exists():
    try:
        br3k.fs_delete_file(TARGET_FILE)
    except Exception:
        pass

def make_target_file(data=TEST_DATA):
    delete_target_if_exists()

    handle = br3k.fs_create_file(TARGET_FILE, file_mode=FsFileMode.ReadWrite)
    buffer = br3k.BufferView(data)
    br3k.fs_write_file(handle, data=buffer.ptr, size=buffer.size)
    del handle

def read_target_bytes():
    mapping = br3k.FileMapping(TARGET_FILE)
    data = mapping.bytes()
    del mapping
    return data

def expect_target_missing():
    try:
        br3k.fs_open_file(TARGET_FILE)
    except Exception:
        return

    raise Exception("target file still exists")

def expect_target_bytes(expected):
    actual = read_target_bytes()

    if actual != expected:
        raise Exception(f"unexpected target file bytes: {actual!r}")

def run_open_file_case(file_open_strategy, file_mode):
    make_target_file()

    handle = br3k.fs_open_file(
        TARGET_FILE,
        file_mode=file_mode,
        file_open_strategy=file_open_strategy,
    )
    del handle

    expect_target_bytes(TEST_DATA)
    delete_target_if_exists()

def run_delete_file_case(file_delete_strategy):
    make_target_file()
    br3k.fs_delete_file(TARGET_FILE, file_delete_strategy=file_delete_strategy)
    expect_target_missing()

def run_change_delete_file_case(file_delete_strategy):
    make_target_file()
    br3k.fs_change_file(
        TARGET_FILE,
        file_change_strategy=FileChangeStrategy.DeleteFile,
        file_delete_strategy=file_delete_strategy,
    )
    expect_target_missing()

def run_change_open_file_case(file_open_strategy):
    make_target_file()
    br3k.fs_change_file(
        TARGET_FILE,
        file_change_strategy=FileChangeStrategy.OpenFile,
        file_open_strategy=file_open_strategy,
    )
    expect_target_bytes(b"\x00" * len(TEST_DATA))
    delete_target_if_exists()

def run_change_create_file_mapping_case():
    make_target_file()
    br3k.fs_change_file(TARGET_FILE, file_change_strategy=FileChangeStrategy.CreateFileMapping)
    expect_target_bytes(b"\x00" * len(TEST_DATA))
    delete_target_if_exists()

def iter_cases():
    for file_open_strategy in enum_items(FileOpenStrategy):
        for file_mode in enum_items(FsFileMode):
            yield (
                FileTestType.OpenFile,
                None,
                file_open_strategy,
                file_mode,
            )

    for file_delete_strategy in enum_items(FileDeleteStrategy):
        yield (
            FileTestType.DeleteFile,
            file_delete_strategy,
            None,
            None,
        )

    for file_delete_strategy in enum_items(FileDeleteStrategy):
        yield (
            FileTestType.ChangeDeleteFile,
            file_delete_strategy,
            None,
            None,
        )

    for file_open_strategy in enum_items(FileOpenStrategy):
        yield (
            FileTestType.ChangeOpenFile,
            None,
            file_open_strategy,
            None,
        )

    yield (
        FileTestType.ChangeCreateFileMapping,
        None,
        None,
        None,
    )

def run_case(file_test_type, file_delete_strategy, file_open_strategy, file_mode):
    if file_test_type == FileTestType.OpenFile:
        run_open_file_case(file_open_strategy, file_mode)
    elif file_test_type == FileTestType.DeleteFile:
        run_delete_file_case(file_delete_strategy)
    elif file_test_type == FileTestType.ChangeDeleteFile:
        run_change_delete_file_case(file_delete_strategy)
    elif file_test_type == FileTestType.ChangeOpenFile:
        run_change_open_file_case(file_open_strategy)
    elif file_test_type == FileTestType.ChangeCreateFileMapping:
        run_change_create_file_mapping_case()
    else:
        raise Exception("unknown file test type")

def format_case(
    sys_api_backend,
    sys_api_dispatch_name,
    file_test_type,
    file_delete_strategy,
    file_open_strategy,
    file_mode,
):
    return (
        f"sys_api_backend={sys_api_backend} / "
        f"sys_api_dispatch={sys_api_dispatch_name} / "
        f"{enum_case_name(file_test_type)} / "
        f"file_delete_strategy={enum_case_name(file_delete_strategy)} / "
        f"file_open_strategy={enum_case_name(file_open_strategy)} / "
        f"file_mode={enum_case_name(file_mode)}"
    )

if __name__ == "__main__":

    print("Script: Test file open, delete, and change techniques")
    print()

    total_count = 0
    failed_count = 0

    for sys_api_backend in SYS_API_BACKEND_CASES:
        for sys_api_dispatch_name, sys_api_dispatch in SYS_API_DISPATCH_CASES:
            init_sysapi(sys_api_backend, sys_api_dispatch)

            for case in iter_cases():
                (
                    file_test_type,
                    file_delete_strategy,
                    file_open_strategy,
                    file_mode,
                ) = case
                case_name = format_case(
                    sys_api_backend,
                    sys_api_dispatch_name,
                    file_test_type,
                    file_delete_strategy,
                    file_open_strategy,
                    file_mode,
                )

                total_count += 1
                print(f"Case: {case_name}")

                try:
                    run_case(
                        file_test_type,
                        file_delete_strategy,
                        file_open_strategy,
                        file_mode,
                    )
                    print(f"Case passed: {case_name}")
                except Exception as e:
                    failed_count += 1
                    print(f"Case failed: {case_name}: {type(e).__name__}: {e}")

                print()

    delete_target_if_exists()

    print(f"Cases completed: {total_count - failed_count}/{total_count}")

    if failed_count > 0:
        raise Exception(f"{failed_count} file case(s) failed")
