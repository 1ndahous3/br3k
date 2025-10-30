#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(unused_imports)]

use libc::*;

use crate::ntwin::{
    LARGE_INTEGER, ULARGE_INTEGER,
    RTL_CRITICAL_SECTION_DEBUG, RTL_CRITICAL_SECTION,
    RTL_SRWLOCK, RTL_CONDITION_VARIABLE, RTL_BARRIER, RTL_RUN_ONCE
};
pub use crate::ntdef::{
    CLONG, PCCHAR, PCSHORT, PCLONG, PCSZ, PPVOID, PCVOID, KIRQL, PKIRQL,
    KPRIORITY, PKPRIORITY, RTL_ATOM, PRTL_ATOM, PHYSICAL_ADDRESS,
    PPHYSICAL_ADDRESS, PSTRING, ANSI_STRING, PANSI_STRING,
    OEM_STRING, POEM_STRING, UTF8_STRING, PUTF8_STRING, PCSTRING,
    PCANSI_STRING, PCOEM_STRING, PKSYSTEM_TIME, _KSYSTEM_TIME,
    LOGICAL, PCLIENT_ID, CLIENT_ID64,
    PUNICODE_STRING, PCUNICODE_STRING, PUNICODE_STRING64,
    OBJECT_ATTRIBUTES, POBJECT_ATTRIBUTES, PCOBJECT_ATTRIBUTES
};
use crate::ntsxs::ACTIVATION_CONTEXT;
use windows_sys::core::{BOOL, GUID};
use windows_sys::Win32::Foundation::{NTSTATUS, HANDLE, UNICODE_STRING, LUID};
use windows_sys::Win32::System::Kernel::{
    SLIST_HEADER, SLIST_ENTRY, LIST_ENTRY, SINGLE_LIST_ENTRY, PROCESSOR_NUMBER,
    RTL_BALANCED_NODE, NT_PRODUCT_TYPE
};
use windows_sys::Win32::System::Diagnostics::Debug::{
    CONTEXT, IMAGE_RUNTIME_FUNCTION_ENTRY, EXCEPTION_POINTERS, EXCEPTION_RECORD,
    IMAGE_NT_HEADERS32, IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER,
    XSAVE_AREA_HEADER, WOW64_CONTEXT
};
use windows_sys::Win32::System::ApplicationInstallationAndServicing::{
    ACTCTX_SECTION_KEYED_DATA, ACTIVATION_CONTEXT_QUERY_INDEX
};
use windows_sys::Win32::System::JobObjects::JOB_SET_ARRAY;
use windows_sys::Win32::Security::{
    ACL, SECURITY_QUALITY_OF_SERVICE, SID_IDENTIFIER_AUTHORITY, LUID_AND_ATTRIBUTES,
    GENERIC_MAPPING, TOKEN_MANDATORY_POLICY, PRIVILEGE_SET, CLAIM_SECURITY_ATTRIBUTES_INFORMATION, SID_AND_ATTRIBUTES,
    SID_AND_ATTRIBUTES_HASH, SECURITY_DESCRIPTOR_CONTROL,
    TOKEN_USER, TOKEN_GROUPS, TOKEN_PRIVILEGES, TOKEN_OWNER, TOKEN_PRIMARY_GROUP,
    TOKEN_DEFAULT_DACL, TOKEN_SOURCE, TOKEN_MANDATORY_LABEL,
    OBJECT_TYPE_LIST
};
use windows_sys::Win32::System::WindowsProgramming::{CLIENT_ID, IMAGE_THUNK_DATA32, IMAGE_THUNK_DATA64, IMAGE_DELAYLOAD_DESCRIPTOR};
use windows_sys::Win32::System::SystemInformation::{GROUP_AFFINITY, OSVERSIONINFOEXW};
use windows_sys::Win32::System::SystemServices::{
    IMAGE_EXPORT_DIRECTORY, IMAGE_RESOURCE_DIRECTORY, IMAGE_BASE_RELOCATION, IMAGE_RESOURCE_DATA_ENTRY,
    IMAGE_RESOURCE_DIRECTORY_STRING, KTMOBJECT_CURSOR
};
use windows_sys::Win32::System::Memory::{MEM_EXTENDED_PARAMETER, CFG_CALL_TARGET_INFO};
use windows_sys::Win32::System::Power::DEVICE_POWER_STATE;
use windows_sys::Win32::Storage::FileSystem::{TRANSACTION_NOTIFICATION, FILE_SEGMENT_ELEMENT};
use windows_sys::Win32::UI::WindowsAndMessaging::MESSAGE_RESOURCE_ENTRY;
use windows_sys::Win32::System::Threading::{LPTHREAD_START_ROUTINE, WAITORTIMERCALLBACK};
use windows_sys::Win32::System::Performance::HardwareCounterProfiling::PERFORMANCE_DATA;

// Basic types
pub type va_list = c_char;
pub type PVOID = *mut c_void;
pub type CHAR = c_char;
pub type WCHAR = wchar_t;
pub type CCHAR = c_char;
pub type CSHORT = c_short;

// Integer types
pub type BYTE = c_uchar;
pub type UCHAR = c_uchar;
pub type USHORT = c_ushort;
pub type ULONG = c_ulong;
pub type LONG = c_long;
pub type LONG64 = i64;
pub type INT = c_int;
pub type UINT = c_uint;
pub type WORD = c_ushort;
pub type DWORD = c_ulong;
pub type DWORD64 = u64;
pub type LONGLONG = i64;
pub type ULONGLONG = u64;
pub type ULONG64 = u64;
pub type ULONG32 = c_uint;

// Boolean types
pub type BOOLEAN = BYTE;

// Pointer and size types
pub type LONG_PTR = isize;
pub type ULONG_PTR = usize;
pub type SIZE_T = ULONG_PTR;

// System types
pub type ACCESS_MASK = DWORD;
pub type KAFFINITY = ULONG_PTR;
pub type LCID = DWORD;
pub type LANGID = WORD;
pub type SECURITY_INFORMATION = DWORD;
pub type NOTIFICATION_MASK = ULONG;
pub type TRACEHANDLE = ULONG64;
pub type CRM_PROTOCOL_ID = GUID;
pub type DLL_DIRECTORY_COOKIE = PVOID;
pub type PDLL_DIRECTORY_COOKIE = *mut DLL_DIRECTORY_COOKIE;

// Pointer types for basic types
pub type PBOOL = *mut BOOL;
pub type PBOOLEAN = *mut BOOLEAN;
pub type PCHAR = *mut CHAR;
pub type PUCHAR = *mut UCHAR;
pub type PUSHORT = *mut USHORT;
pub type PLONG = *mut LONG;
pub type PLONG64 = *mut LONG64;
pub type PULONG = *mut ULONG;
pub type PLONGLONG = *mut LONGLONG;
pub type PULONGLONG = *mut ULONGLONG;
pub type PULONG64 = *mut ULONG64;
pub type PULONG_PTR = *mut ULONG_PTR;
pub type PSIZE_T = *mut SIZE_T;
pub type PDWORD = *mut DWORD;

pub type LPCWCH = *const WCHAR;
pub type PCWCH = *const WCHAR;
pub type PWCH = *mut WCHAR;
pub type LPCWCHAR = *const WCHAR;
pub type PWCHAR = *mut WCHAR;
pub type PCWCHAR = *const WCHAR;
pub type PZZWSTR = *mut WCHAR;
pub type PCZZWSTR = *const WCHAR;
pub type LPCWSTR = *const WCHAR;
pub type LPCCH = *const CHAR;
pub type PCCH = *const CHAR;
pub type LPCH = *mut CHAR;
pub type PCH = *mut CHAR;

// Windows API pointer types
pub type PNTSTATUS = *mut NTSTATUS;
pub type PHANDLE = *mut HANDLE;
pub type PLCID = *mut LCID;
pub type PLUID = *mut LUID;
pub type PGUID = *mut GUID;
pub type PCGUID = *const GUID;
pub type LPGUID = *mut GUID;
pub type LPCGUID = *const GUID;
pub type PACCESS_MASK = *mut ACCESS_MASK;
pub type PCRM_PROTOCOL_ID = *mut CRM_PROTOCOL_ID;
pub type PEXCEPTION_POINTERS = *mut EXCEPTION_POINTERS;
pub type _EXCEPTION_RECORD = EXCEPTION_RECORD; // https://github.com/winsiderss/phnt/pull/55
pub type PEXCEPTION_RECORD = *mut EXCEPTION_RECORD;
pub type PLARGE_INTEGER = *mut LARGE_INTEGER;
pub type PULARGE_INTEGER = *mut ULARGE_INTEGER;
pub type PCONTEXT = *mut CONTEXT;
pub type PPROCESSOR_NUMBER = *mut PROCESSOR_NUMBER;
pub type PSECURITY_INFORMATION = *mut SECURITY_INFORMATION;
pub type PSECURITY_QUALITY_OF_SERVICE = *mut SECURITY_QUALITY_OF_SERVICE;
pub type PSID_IDENTIFIER_AUTHORITY = *mut SID_IDENTIFIER_AUTHORITY;
pub type PSID_AND_ATTRIBUTES = *mut SID_AND_ATTRIBUTES;
pub type PSID_AND_ATTRIBUTES_HASH = *mut SID_AND_ATTRIBUTES_HASH;
pub type PSECURITY_DESCRIPTOR_CONTROL = *mut SECURITY_DESCRIPTOR_CONTROL;
pub type PLUID_AND_ATTRIBUTES  = *mut LUID_AND_ATTRIBUTES;
pub type PGENERIC_MAPPING = *mut GENERIC_MAPPING;
pub type PTOKEN_MANDATORY_POLICY = *mut TOKEN_MANDATORY_POLICY;
pub type PPRIVILEGE_SET = *mut PRIVILEGE_SET;
pub type PCLAIM_SECURITY_ATTRIBUTES_INFORMATION = *mut CLAIM_SECURITY_ATTRIBUTES_INFORMATION;
pub type PACL = *mut ACL;
pub type PPERFORMANCE_DATA = *mut PERFORMANCE_DATA;
pub type PTOKEN_USER = *mut TOKEN_USER;
pub type PTOKEN_GROUPS = *mut TOKEN_GROUPS;
pub type PTOKEN_PRIVILEGES = *mut TOKEN_PRIVILEGES;
pub type PTOKEN_OWNER = *mut TOKEN_OWNER;
pub type PTOKEN_PRIMARY_GROUP = *mut TOKEN_PRIMARY_GROUP;
pub type PTOKEN_DEFAULT_DACL = *mut TOKEN_DEFAULT_DACL;
pub type PTOKEN_SOURCE = *mut TOKEN_SOURCE;
pub type PTOKEN_MANDATORY_LABEL = *mut TOKEN_MANDATORY_LABEL;
pub type POBJECT_TYPE_LIST = *mut OBJECT_TYPE_LIST;
pub type PSE_SIGNING_LEVEL = *mut SE_SIGNING_LEVEL;
pub type PPROFILE_SOURCE_INFO = PVOID;

pub type KSYSTEM_TIME = _KSYSTEM_TIME;
pub type RTL_RESOURCE_DEBUG = RTL_CRITICAL_SECTION_DEBUG;
pub type RTL_OSVERSIONINFOEXW = OSVERSIONINFOEXW;
pub type PTHREAD_START_ROUTINE = LPTHREAD_START_ROUTINE;
pub type WAITORTIMERCALLBACKFUNC = WAITORTIMERCALLBACK;
pub type SE_SIGNING_LEVEL = u32;

pub type PRTL_OSVERSIONINFOEXW = *mut RTL_OSVERSIONINFOEXW;
pub type PRTL_CRITICAL_SECTION_DEBUG = *mut RTL_CRITICAL_SECTION_DEBUG;
pub type PRTL_RESOURCE_DEBUG = *mut RTL_RESOURCE_DEBUG;
pub type PRTL_CRITICAL_SECTION = *mut RTL_CRITICAL_SECTION;
pub type PSLIST_HEADER = *mut SLIST_HEADER;
pub type PSLIST_ENTRY = *mut SLIST_ENTRY;
pub type PLIST_ENTRY = *mut LIST_ENTRY;
pub type PSINGLE_LIST_ENTRY = *mut SINGLE_LIST_ENTRY;
pub type PRTL_BALANCED_NODE = *mut RTL_BALANCED_NODE;
pub type PRTL_SRWLOCK = *mut RTL_SRWLOCK;
pub type PRTL_CONDITION_VARIABLE = *mut RTL_CONDITION_VARIABLE;
pub type PRTL_BARRIER = *mut RTL_BARRIER;
pub type PRTL_RUN_ONCE = *mut RTL_RUN_ONCE;
pub type PJOB_SET_ARRAY = *mut JOB_SET_ARRAY;
pub type RUNTIME_FUNCTION = IMAGE_RUNTIME_FUNCTION_ENTRY;
pub type PRUNTIME_FUNCTION = *mut RUNTIME_FUNCTION;
pub type PACTCTX_SECTION_KEYED_DATA = *mut ACTCTX_SECTION_KEYED_DATA;
pub type PACTIVATION_CONTEXT_QUERY_INDEX = *mut ACTIVATION_CONTEXT_QUERY_INDEX;
pub type PGROUP_AFFINITY = *mut GROUP_AFFINITY;
pub type PDEVICE_POWER_STATE = *mut DEVICE_POWER_STATE;
pub type PKTMOBJECT_CURSOR = *mut KTMOBJECT_CURSOR;
pub type PTRANSACTION_NOTIFICATION = *mut TRANSACTION_NOTIFICATION;
pub type PFILE_SEGMENT_ELEMENT = *mut FILE_SEGMENT_ELEMENT;
pub type PIMAGE_EXPORT_DIRECTORY = *mut IMAGE_EXPORT_DIRECTORY;
pub type PIMAGE_RESOURCE_DIRECTORY = *mut IMAGE_RESOURCE_DIRECTORY;
pub type PIMAGE_BASE_RELOCATION = *mut IMAGE_BASE_RELOCATION;
pub type PIMAGE_RESOURCE_DATA_ENTRY = *mut IMAGE_RESOURCE_DATA_ENTRY;
pub type PIMAGE_RESOURCE_DIRECTORY_STRING = *mut IMAGE_RESOURCE_DIRECTORY_STRING;
pub type PCIMAGE_DELAYLOAD_DESCRIPTOR = *const IMAGE_DELAYLOAD_DESCRIPTOR;
#[cfg(target_pointer_width = "64")]
pub type PIMAGE_THUNK_DATA = *mut IMAGE_THUNK_DATA64;
#[cfg(target_pointer_width = "32")]
pub type PIMAGE_THUNK_DATA = *mut IMAGE_THUNK_DATA32;
#[cfg(target_pointer_width = "64")]
pub type PIMAGE_NT_HEADERS = *mut IMAGE_NT_HEADERS64;
#[cfg(target_pointer_width = "32")]
pub type PIMAGE_NT_HEADERS = *mut IMAGE_NT_HEADERS32;
pub type PIMAGE_SECTION_HEADER = *mut IMAGE_SECTION_HEADER;
pub type PWOW64_CONTEXT = *mut WOW64_CONTEXT;
pub type PXSAVE_AREA_HEADER = *mut XSAVE_AREA_HEADER;
pub type PMEM_EXTENDED_PARAMETER = *mut MEM_EXTENDED_PARAMETER;
pub type PCFG_CALL_TARGET_INFO = *mut CFG_CALL_TARGET_INFO;
pub type PMESSAGE_RESOURCE_ENTRY = *mut MESSAGE_RESOURCE_ENTRY;
pub type PNT_PRODUCT_TYPE  = *mut NT_PRODUCT_TYPE;

pub type PENCLAVE_ROUTINE = Option<
    unsafe extern "system" fn(lpThreadParameter: PVOID) -> PVOID
>;

// RPC types
pub type CLSID = GUID;
pub type IID = GUID;
pub type error_status_t = *mut c_void;

pub const MAX_PATH: usize = 260;
pub const PS_ATTRIBUTE_NUMBER_MASK: u32 = 65535;
pub const PS_ATTRIBUTE_THREAD: u32 = 65536;
pub const PS_ATTRIBUTE_INPUT: u32 = 131072;
pub const PS_ATTRIBUTE_ADDITIVE: u32 = 262144;

pub const fn ps_attribute_value(number: u32, thread: bool, input: bool, additive: bool) -> u32 {
    (number & crate::ntpsapi::PS_ATTRIBUTE_NUMBER_MASK) |
        if thread { crate::ntpsapi::PS_ATTRIBUTE_THREAD } else { 0 } |
        if input { crate::ntpsapi::PS_ATTRIBUTE_INPUT } else { 0 } |
        if additive { crate::ntpsapi::PS_ATTRIBUTE_ADDITIVE } else { 0 }
}

pub const PS_ATTRIBUTE_PARENT_PROCESS: u32 =
    ps_attribute_value(crate::ntpsapi::PS_ATTRIBUTE_NUM::PsAttributeParentProcess as u32, false, true, true);
pub const PS_ATTRIBUTE_DEBUG_OBJECT: u32 =
    ps_attribute_value(crate::ntpsapi::PS_ATTRIBUTE_NUM::PsAttributeDebugObject as u32, false, true, true);
pub const PS_ATTRIBUTE_TOKEN: u32 =
    ps_attribute_value(crate::ntpsapi::PS_ATTRIBUTE_NUM::PsAttributeToken as u32, false, true, true);
pub const PS_ATTRIBUTE_CLIENT_ID: u32 =
    ps_attribute_value(crate::ntpsapi::PS_ATTRIBUTE_NUM::PsAttributeClientId as u32, true, false, false);
pub const PS_ATTRIBUTE_TEB_ADDRESS: u32 =
    ps_attribute_value(crate::ntpsapi::PS_ATTRIBUTE_NUM::PsAttributeTebAddress as u32, true, false, false);
pub const PS_ATTRIBUTE_IMAGE_NAME: u32 =
    ps_attribute_value(crate::ntpsapi::PS_ATTRIBUTE_NUM::PsAttributeImageName as u32, false, true, false);
pub const PS_ATTRIBUTE_IMAGE_INFO: u32 =
    ps_attribute_value(crate::ntpsapi::PS_ATTRIBUTE_NUM::PsAttributeImageInfo as u32, false, false, false);
pub const PS_ATTRIBUTE_MEMORY_RESERVE: u32 =
    ps_attribute_value(crate::ntpsapi::PS_ATTRIBUTE_NUM::PsAttributeMemoryReserve as u32, false, true, false);
pub const PS_ATTRIBUTE_PRIORITY_CLASS: u32 =
    ps_attribute_value(crate::ntpsapi::PS_ATTRIBUTE_NUM::PsAttributePriorityClass as u32, false, true, false);
pub const PS_ATTRIBUTE_ERROR_MODE: u32 =
    ps_attribute_value(crate::ntpsapi::PS_ATTRIBUTE_NUM::PsAttributeErrorMode as u32, false, true, false);
pub const PS_ATTRIBUTE_STD_HANDLE_INFO: u32 =
    ps_attribute_value(crate::ntpsapi::PS_ATTRIBUTE_NUM::PsAttributeStdHandleInfo as u32, false, true, false);
pub const PS_ATTRIBUTE_HANDLE_LIST: u32 =
    ps_attribute_value(crate::ntpsapi::PS_ATTRIBUTE_NUM::PsAttributeHandleList as u32, false, true, false);
pub const PS_ATTRIBUTE_GROUP_AFFINITY: u32 =
    ps_attribute_value(crate::ntpsapi::PS_ATTRIBUTE_NUM::PsAttributeGroupAffinity as u32, true, true, false);
pub const PS_ATTRIBUTE_PREFERRED_NODE: u32 =
    ps_attribute_value(crate::ntpsapi::PS_ATTRIBUTE_NUM::PsAttributePreferredNode as u32, false, true, false);
pub const PS_ATTRIBUTE_IDEAL_PROCESSOR: u32 =
    ps_attribute_value(crate::ntpsapi::PS_ATTRIBUTE_NUM::PsAttributeIdealProcessor as u32, true, true, false);
pub const PS_ATTRIBUTE_UMS_THREAD: u32 =
    ps_attribute_value(crate::ntpsapi::PS_ATTRIBUTE_NUM::PsAttributeUmsThread as u32, true, true, false);
pub const PS_ATTRIBUTE_MITIGATION_OPTIONS: u32 =
    ps_attribute_value(crate::ntpsapi::PS_ATTRIBUTE_NUM::PsAttributeMitigationOptions as u32, false, true, false);
pub const PS_ATTRIBUTE_PROTECTION_LEVEL: u32 =
    ps_attribute_value(crate::ntpsapi::PS_ATTRIBUTE_NUM::PsAttributeProtectionLevel as u32, false, true, true);
pub const PS_ATTRIBUTE_SECURE_PROCESS: u32 =
    ps_attribute_value(crate::ntpsapi::PS_ATTRIBUTE_NUM::PsAttributeSecureProcess as u32, false, true, false);
pub const PS_ATTRIBUTE_JOB_LIST: u32 =
    ps_attribute_value(crate::ntpsapi::PS_ATTRIBUTE_NUM::PsAttributeJobList as u32, false, true, false);
pub const PS_ATTRIBUTE_CHILD_PROCESS_POLICY: u32 =
    ps_attribute_value(crate::ntpsapi::PS_ATTRIBUTE_NUM::PsAttributeChildProcessPolicy as u32, false, true, false);
pub const PS_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY: u32 =
    ps_attribute_value(crate::ntpsapi::PS_ATTRIBUTE_NUM::PsAttributeAllApplicationPackagesPolicy as u32, false, true, false);
pub const PS_ATTRIBUTE_WIN32K_FILTER: u32 =
    ps_attribute_value(crate::ntpsapi::PS_ATTRIBUTE_NUM::PsAttributeWin32kFilter as u32, false, true, false);
pub const PS_ATTRIBUTE_SAFE_OPEN_PROMPT_ORIGIN_CLAIM: u32 =
    ps_attribute_value(crate::ntpsapi::PS_ATTRIBUTE_NUM::PsAttributeSafeOpenPromptOriginClaim as u32, false, true, false);
pub const PS_ATTRIBUTE_BNO_ISOLATION: u32 =
    ps_attribute_value(crate::ntpsapi::PS_ATTRIBUTE_NUM::PsAttributeBnoIsolation as u32, false, true, false);
pub const PS_ATTRIBUTE_DESKTOP_APP_POLICY: u32 =
    ps_attribute_value(crate::ntpsapi::PS_ATTRIBUTE_NUM::PsAttributeDesktopAppPolicy as u32, false, true, false);
pub const PS_ATTRIBUTE_CHPE: u32 =
    ps_attribute_value(crate::ntpsapi::PS_ATTRIBUTE_NUM::PsAttributeChpe as u32, false, true, true);
pub const PS_ATTRIBUTE_MITIGATION_AUDIT_OPTIONS: u32 =
    ps_attribute_value(crate::ntpsapi::PS_ATTRIBUTE_NUM::PsAttributeMitigationAuditOptions as u32, false, true, false);
pub const PS_ATTRIBUTE_MACHINE_TYPE: u32 =
    ps_attribute_value(crate::ntpsapi::PS_ATTRIBUTE_NUM::PsAttributeMachineType as u32, false, true, true);
pub const PS_ATTRIBUTE_COMPONENT_FILTER: u32 =
    ps_attribute_value(crate::ntpsapi::PS_ATTRIBUTE_NUM::PsAttributeComponentFilter as u32, false, true, false);
pub const PS_ATTRIBUTE_ENABLE_OPTIONAL_XSTATE_FEATURES: u32 =
    ps_attribute_value(crate::ntpsapi::PS_ATTRIBUTE_NUM::PsAttributeEnableOptionalXStateFeatures as u32, true, true, false);


pub const NT_CURRENT_PROCESS: HANDLE = -1isize as HANDLE;
pub const NT_CURRENT_THREAD: HANDLE = -2isize as HANDLE;
pub const NT_CURRENT_SESSION: HANDLE = -3isize as HANDLE;

pub type PPS_APC_ROUTINE = PVOID;
pub type PIO_APC_ROUTINE = PVOID;
pub type PUSER_THREAD_START_ROUTINE = PVOID;

pub const DUPLICATE_CLOSE_SOURCE: ULONG = 0x00000001;
pub const DUPLICATE_SAME_ACCESS: ULONG = 0x00000002;
pub const DUPLICATE_SAME_ATTRIBUTES: ULONG = 0x00000004;

//

use windows_sys::Win32::Storage::FileSystem::{STANDARD_RIGHTS_READ, STANDARD_RIGHTS_WRITE, STANDARD_RIGHTS_EXECUTE, STANDARD_RIGHTS_REQUIRED, SYNCHRONIZE};

pub const TRANSACTION_QUERY_INFORMATION: u32 = 0x0001;
pub const TRANSACTION_SET_INFORMATION: u32 = 0x0002;
pub const TRANSACTION_ENLIST: u32 = 0x0004;
pub const TRANSACTION_COMMIT: u32 = 0x0008;
pub const TRANSACTION_ROLLBACK: u32 = 0x0010;
pub const TRANSACTION_PROPAGATE: u32 = 0x0020;
pub const TRANSACTION_RIGHT_RESERVED1: u32 = 0x0040;

pub const TRANSACTION_GENERIC_READ: u32 =
        STANDARD_RIGHTS_READ |
        TRANSACTION_QUERY_INFORMATION |
        SYNCHRONIZE;

pub const TRANSACTION_GENERIC_WRITE: u32 =
        STANDARD_RIGHTS_WRITE |
        TRANSACTION_SET_INFORMATION |
        TRANSACTION_COMMIT |
        TRANSACTION_ENLIST |
        TRANSACTION_ROLLBACK |
        TRANSACTION_PROPAGATE |
        SYNCHRONIZE;

pub const TRANSACTION_GENERIC_EXECUTE: u32 =
        STANDARD_RIGHTS_EXECUTE |
        TRANSACTION_COMMIT |
        TRANSACTION_ROLLBACK |
        SYNCHRONIZE;

pub const TRANSACTION_ALL_ACCESS: u32 =
        STANDARD_RIGHTS_REQUIRED |
        TRANSACTION_GENERIC_READ |
        TRANSACTION_GENERIC_WRITE |
        TRANSACTION_GENERIC_EXECUTE;

pub const TRANSACTION_RESOURCE_MANAGER_RIGHTS: u32 =
        TRANSACTION_GENERIC_READ |
        STANDARD_RIGHTS_WRITE |
        TRANSACTION_SET_INFORMATION |
        TRANSACTION_ENLIST |
        TRANSACTION_ROLLBACK |
        TRANSACTION_PROPAGATE |
        SYNCHRONIZE;

use windows_sys::Win32::System::Diagnostics::Debug::CONTEXT_FLAGS;

#[cfg(target_arch = "x86_64")]
pub const CONTEXT_FULL: CONTEXT_FLAGS = windows_sys::Win32::System::Diagnostics::Debug::CONTEXT_FULL_AMD64;

#[cfg(target_arch = "x86")]
pub const CONTEXT_FULL: CONTEXT_FLAGS = windows_sys::Win32::System::Diagnostics::Debug::CONTEXT_FULL_X86;