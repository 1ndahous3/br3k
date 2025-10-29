use std::thread;
use std::time::Duration;

use windows_sys::Win32::Foundation::HINSTANCE;
use windows_sys::Win32::System::SystemServices::{
    DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH
};

use br3k::ipc;
use br3k::logging;
use br3k::python;
use br3k::{sysapi, sysapi_ctx};

use windef::ntstatus;

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
            logging::init(true, true);
            logging::log_header();

            let pid: u32 = unsafe { (*sysapi::teb()).ClientId.UniqueProcess } as _;
            log::info!("Mode: IPC client ({pid})");

            sysapi_ctx::SysApiCtx::init(sysapi_ctx::InitOptions {
                ntdll_copy: false,
                ntdll_alt_api: false,
            });


            for _ in 0..10 {
                match ipc::open_pipe(pid) {
                    Ok(pipe_handle) => {

                        let script_data = ipc::receive_data(*pipe_handle.get())
                            .map_err(|status| {
                                log::error!("Unable to read script from pipe: {}", sysapi::ntstatus_decode(status));
                                std::process::exit(1);
                            }).unwrap();

                        let script = String::from_utf8(script_data).unwrap();

                        let py = python::py_module::PythonCore::new();
                        match py.execute_script(&script) {
                            Ok(_) => {
                                log::info!("Script executed successfully.");
                            }
                            Err(e) => {
                                log::error!("Error executing script: {}", e);
                                std::process::exit(1);
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
                        std::process::exit(1);
                    }
                }
            }

            log::error!("Unable to open the pipe: server did not create the pipe");
            std::process::exit(1);
        },
        DLL_PROCESS_DETACH => (),
        _ => ()
    }

    true
}
