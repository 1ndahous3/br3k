use clap::{Arg, Command};

use br3k::ipc;
use br3k::logging;
use br3k::sysapi;
use br3k::sysapi_ctx;
use br3k::vm;

fn main() {

    if let Err(e) = logging::init(true, false) {
        log::error!("Unable to initialize logger: {e}");
    }

    logging::log_header();

    let matches = Command::new("br3k")
        .arg(
            Arg::new("script")
                .long("script")
                .help("Path to the Python script to execute"),
        )
        .get_matches();

    if let Some(script_path) = matches.get_one::<String>("script") {
        log::info!("Mode: script file ({})", script_path);
        let script_data = match std::fs::read_to_string(script_path) {
            Ok(script_data) => script_data,
            Err(e) => {
                log::error!("Unable to open script file: {e}");
                std::process::exit(1);
            }
        };

        let vm = vm::Vm::default();
        match vm.execute_script(&script_data, Some(script_path.clone())) {
            Ok(_) => {
                log::info!("Script executed successfully");
            }
            Err(_) => {
                log::error!("Error executing script");
                std::process::exit(1);
            }
        }
    } else {
        let pid: u32 = unsafe { (*sysapi::teb()).ClientId.UniqueProcess } as _;
        log::info!("Mode: IPC client ({pid})");

        if let Err(e) = sysapi_ctx::SysApiCtx::init(sysapi_ctx::InitOptions {
            ntdll_copy: false,
            ntdll_alt_api: false,
        }) {
            log::error!("Unable to initialize system API context: {e}");
            std::process::exit(1);
        }

        let pipe_handle = match ipc::open_pipe(pid as _) {
            Ok(pipe_handle) => pipe_handle,
            Err(error) => {
                log::error!("Unable to open pipe: {error}");
                std::process::exit(1);
            }
        };

        let script_data = match ipc::receive_data(*pipe_handle.get()) {
            Ok(script_data) => script_data,
            Err(error) => {
                log::error!("Unable to read script from pipe: {error}");
                std::process::exit(1);
            }
        };

        let script = match String::from_utf8(script_data) {
            Ok(script) => script,
            Err(e) => {
                log::error!("IPC script is not valid UTF-8: {e}");
                std::process::exit(1);
            }
        };

        let vm = vm::Vm::default();
        match vm.execute_script(&script, None) {
            Ok(_) => {
                log::info!("Script executed successfully");
            }
            Err(_) => {
                log::error!("Error executing script");
                std::process::exit(1);
            }
        }
    }
}
