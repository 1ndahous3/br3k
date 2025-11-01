#![feature(panic_update_hook)]
use std::panic;
use std::backtrace;
use std::thread;
use std::sync::OnceLock;
use std::time::Duration;

use windef::ntstatus;
use windows_sys::Win32::Foundation::HINSTANCE;
use windows_sys::Win32::System::SystemServices::{
    DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH
};

use br3k::ipc;
use br3k::logging;
use br3k::vm;
use br3k::{sysapi, sysapi_ctx};


// Backtrace causes deadlock if panic occurs not
// on DLL_PROCESS_ATTACH (because it loads dbghelp.dll during fmt::Display)
// so for debugging with backtrace main payload will be executed
// on DLL_PROCESS_ATTACH (without separate thread)
const PANIC_BACKTRACE: bool = true;

static PAYLOAD_WORKER_DEAD: OnceLock<()> = OnceLock::new();

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
                            Err(_) =>
                                log::error!("Error executing script")
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
    PAYLOAD_WORKER_DEAD.set(()).unwrap();
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

                log::error!("Panic: {info}");
                if PANIC_BACKTRACE {
                    let backtrace = backtrace::Backtrace::capture();
                    log::error!("Backtrace:\n {backtrace}");
                }

                prev(info);
                PAYLOAD_WORKER_DEAD.set(()).unwrap();
            });

            // it's too hard to see what's going on in context of remote process without logs
            if logging::init(false, true).is_err() {
                PAYLOAD_WORKER_DEAD.set(()).unwrap();
                return false;
            }

            logging::log_header();

            sysapi_ctx::SysApiCtx::init(sysapi_ctx::InitOptions {
                ntdll_copy: false,
                ntdll_alt_api: false,
            });

            if PANIC_BACKTRACE {
                main();
                PAYLOAD_WORKER_DEAD.set(()).unwrap();
            }
            else {
                // https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-best-practices
                match sysapi::create_thread(windef::winbase::NT_CURRENT_PROCESS, main as _, None) {
                    Err(status) => {
                        log::error!("Unable to create payload thread: {}", sysapi::ntstatus_decode(status));
                        PAYLOAD_WORKER_DEAD.set(()).unwrap();
                    },
                    Ok(_) =>
                        log::info!("Payload thread created")
                }
            }
        },
        DLL_PROCESS_DETACH => {
            if PAYLOAD_WORKER_DEAD.get().is_none() {
                log::warn!("Unloading DLL while payload is active, holding...");
                PAYLOAD_WORKER_DEAD.wait();
            }

            log::info!("Shutting down...");
        },
        _ => ()
    }

    true
}
