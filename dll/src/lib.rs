#![feature(panic_update_hook)]
use std::panic;
use std::backtrace;

use std::thread;
use std::time::Duration;

use windows_sys::Win32::Foundation::HINSTANCE;
use windows_sys::Win32::System::SystemServices::{
    DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH
};

use br3k::ipc;
use br3k::logging;
use br3k::vm;
use br3k::{sysapi, sysapi_ctx};

use windef::ntstatus;

extern "system" fn main() {

    let pid: u32 = unsafe { (*sysapi::teb()).ClientId.UniqueProcess } as _;

    for _ in 0..10 {
        match ipc::open_pipe(pid) {
            Ok(pipe_handle) => {

                match ipc::receive_data(*pipe_handle.get()) {
                    Err(status) =>
                        log::error!("Unable to read script from pipe: {}", sysapi::ntstatus_decode(status)),
                    Ok(script_data) => {
                        let script = String::from_utf8(script_data).unwrap();

                        let vm = vm::Vm::default();
                        match vm.execute_script(&script, None) {
                            Ok(_) =>
                                log::info!("Script executed successfully"),
                            Err(e) =>
                                log::error!("Error executing script: {e}")
                        }
                    }
                }
            },
            Err(status) => {

                if status.0 == ntstatus::STATUS_OBJECT_NAME_NOT_FOUND {
                    log::warn!("Server did not create the pipe, waiting...");
                    thread::sleep(Duration::from_secs(1));
                    continue;
                }

                log::error!("Unable to open the pipe: {}", sysapi::ntstatus_decode(status));
            }
        }
    }

    log::error!("Unable to open the pipe: server did not create the pipe");
}

#[unsafe(no_mangle)]
#[allow(non_snake_case, unused_variables)]
extern "system" fn DllMain(
    dll_module: HINSTANCE,
    call_reason: u32,
    _: *mut ())
    -> bool
{
    match call_reason {
        DLL_PROCESS_ATTACH => {

            unsafe { std::env::set_var("RUST_BACKTRACE", "1"); }
            panic::update_hook(move |prev, info| {
                let backtrace = backtrace::Backtrace::capture();
                log::error!("Panic: {info}");
                log::error!("Backtrace:\n {backtrace}");
                prev(info);
            });

            // it's too hard to see what's going on in context of remote process without logs
            if logging::init(false, true).is_err() {
                return false;
            }

            logging::log_header();

            sysapi_ctx::SysApiCtx::init(sysapi_ctx::InitOptions {
                ntdll_copy: false,
                ntdll_alt_api: false,
            });

            // https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-best-practices
            match sysapi::create_thread(windef::winbase::NT_CURRENT_PROCESS, main as _, None) {
                Err(status) =>
                    log::error!("Unable to create payload thread: {}", sysapi::ntstatus_decode(status)),
                Ok(thread_handle) => {
                    log::info!("Payload thread created");
                    thread_handle.release();
                }
            }
        },
        DLL_PROCESS_DETACH => {
            log::warn!("Shutting down...");
        },
        _ => ()
    }

    true
}
