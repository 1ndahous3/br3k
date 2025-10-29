use regex::Regex;
use std::fs;
use std::path::PathBuf;

use rayon::prelude::*;

fn main() {
    let defines = [
        ("_WIN32", None),
        ("_WIN64", None),
        ("PHNT_INLINE_FREE_FORWARDERS", None),
        ("PHNT_VERSION", Some("PHNT_WIN11_24H2")),
        ("_MSC_VER", Some("1900")),
    ];

    let all_modules = [
        ("ntpebteb", "ntpebteb.h"),
        ("ntpsapi", "ntpsapi.h"),
        ("ntexapi", "ntexapi.h"),
        ("ntmmapi", "ntmmapi.h"),
        ("ntobapi", "ntobapi.h"),
        ("ntioapi", "ntioapi.h"),
        ("nttmapi", "nttmapi.h"),
        ("ntpoapi", "ntpoapi.h"),
        ("ntkeapi", "ntkeapi.h"),
        ("ntseapi", "ntseapi.h"),
        ("ntlpcapi", "ntlpcapi.h"),
        ("ntldr", "ntldr.h"),
        ("ntsxs", "ntsxs.h"),
        ("ntrtl", "ntrtl.h"),
        ("ntnls", "ntnls.h"),
    ];

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/winbase.rs");
    println!("cargo:rerun-if-changed=src/ntstatus.rs");
    println!("cargo:rerun-if-changed=src/ntwin.h");

    let phnt_path_str = std::env::var("PHNT_PATH")
        .expect("PHNT_PATH environment variable must be set")
        .replace("\\", "/"); // BUG: clang works only with linux separators in allowlist_file()

    let mut phnt_path = PathBuf::from(phnt_path_str);
    if !phnt_path.is_absolute() {
        // relative to workspace -> relative to build script
        phnt_path = PathBuf::from(format!("../{}", phnt_path.display()));
    };

    let out_dir = PathBuf::from("src/generated");
    fs::create_dir_all(&out_dir).unwrap();

    let mut modules = all_modules.to_vec();

    // [special cases]

    // not from PHNT, implemented missing types
    modules.push(("ntwin", "src/ntwin.h"));
    modules.push(("rpcwin", "src/rpcwin.h"));

    // RPC stuff
    modules.push(("rpc_lclor", "src/rpc/lclor.h"));
    modules.push(("rpc_rundown", "src/rpc/rundown.h"));

    // because of generation duplicates with windows_sys, it will be included only in ntwin
    modules.push(("ntdef", "phnt_ntdef.h"));

    let winbase_module = PathBuf::from("src/winbase.rs");
    fs::copy(&winbase_module, format!("{}/winbase.rs", out_dir.display()))
        .expect("Failed to copy winbase.rs");

    let ntstatus_module = PathBuf::from("src/ntstatus.rs");
    fs::copy(&ntstatus_module, format!("{}/ntstatus.rs", out_dir.display()))
        .expect("Failed to copy ntstatus.rs");

    // println!("cargo:rerun-if-changed={}", ntstatus_module.display());

    modules.par_iter().for_each(|module| {
        let header_path =
            if module.0.starts_with("rpc") || module.0 == "ntwin" {
                PathBuf::from(module.1)
            } else {
                PathBuf::from(format!("{}/{}", phnt_path.display(), module.1))
            };

        let out_file = out_dir.join(format!("{}.rs", module.0));

        let mut builder = bindgen::Builder::default()
            .anon_fields_prefix("a")
            .header(header_path.to_str().unwrap())
            .clang_arg(format!("-include{}/phnt_windows.h", phnt_path.display()))
            .clang_arg(format!("-include{}/phnt.h", phnt_path.display()))
            .clang_arg("-includehstring.h")
            .clang_arg(format!("-I{}", phnt_path.display()))
            .blocklist_type("WNF_STATE_NAME") // windows_sys::Win32::System::Kernel::*
            .blocklist_type("PPS_APC_ROUTINE") //
            .blocklist_type("PIO_APC_ROUTINE") //
            .blocklist_type("PUSER_THREAD_START_ROUTINE") //
            .default_enum_style(bindgen::EnumVariation::Rust {
                non_exhaustive: false,
            })
            .derive_default(true)
            .derive_copy(true)
            .derive_debug(true)
            .allowlist_recursively(false);

        for (k, v) in &defines {
            match v {
                Some(val) => {
                    builder = builder.clang_arg(format!("-D{k}={val}"));
                }
                None => {
                    builder = builder.clang_arg(format!("-D{k}"));
                }
            }
        }

        let bindings = builder
            .allowlist_file(header_path.to_str().unwrap())
            .generate()
            .expect(&format!("Unable to generate bindings for {}", module.1));

        bindings
            .write_to_file(&out_file)
            .expect("Couldn't write bindings!");

        generate_cross_use(&out_file, &modules, module.0);
        generate_pfn_types(&out_file);

        //println!("cargo:rerun-if-changed={}", module.1);
    });

    generate_mod_rs(&out_dir, &modules);
}

fn generate_cross_use(file_path: &PathBuf, modules: &[(&str, &str)], module: &str) {
    let content = fs::read_to_string(file_path).expect("Failed to read generated file");
    let mut header = String::new();

    header.push_str("#![allow(non_camel_case_types)]\n");
    header.push_str("#![allow(non_snake_case)]\n");
    header.push_str("#![allow(non_upper_case_globals)]\n");
    header.push_str("#![allow(unsafe_op_in_unsafe_fn)]\n");
    header.push_str("#![allow(unused_imports)]\n");
    header.push_str("#![allow(unnecessary_transmutes)]\n\n");
    header.push_str("use crate::winbase::*;\n\n");
    header.push_str("use winapi::shared::rpcdce::*;\n");
    header.push_str("use winapi::shared::rpcndr::*;\n");
    header.push_str("use windows_sys::core::*;\n");
    header.push_str("use windows_sys::Win32::Foundation::*;\n");
    header.push_str("use windows_sys::Win32::System::WindowsProgramming::*;\n");
    header.push_str("use windows_sys::Win32::System::Kernel::*;\n");
    header.push_str("use windows_sys::Win32::System::Ioctl::*;\n");
    header.push_str("use windows_sys::Win32::System::Diagnostics::Debug::*;\n");
    header.push_str("use windows_sys::Win32::System::SystemInformation::*;\n");
    header.push_str("use windows_sys::Win32::System::JobObjects::*;\n");
    header.push_str("use windows_sys::Win32::System::Threading::*;\n");
    header.push_str("use windows_sys::Win32::System::Performance::HardwareCounterProfiling::*;\n");
    header.push_str("use windows_sys::Win32::System::SystemServices::*;\n");
    header.push_str("use windows_sys::Win32::System::Power::*;\n");
    header.push_str("use windows_sys::Win32::System::ApplicationInstallationAndServicing::*;\n");
    header.push_str("use windows_sys::Win32::System::Memory::*;\n");
    header.push_str("use windows_sys::Win32::Storage::FileSystem::*;\n");
    header.push_str("use windows_sys::Win32::Security::*;\n");
    for other_module in modules {
        if other_module.0 == "ntdef" || other_module.0 == module {
            continue;
        }

        header.push_str(&format!("use crate::{}::*;\n", other_module.0));
    }

    fs::write(file_path, format!("{header}\n{content}"))
        .expect("Failed to write updated file");
}

fn generate_mod_rs(out_dir: &PathBuf, modules: &[(&str, &str)]) {
    let mut content = String::new();

    content.push_str("pub mod winbase;\n");
    content.push_str("pub mod ntstatus;\n");

    for module in modules {
        content.push_str(&format!("pub mod {};\n", module.0));
    }

    let mod_path = out_dir.join("mod.rs");
    fs::write(mod_path, content)
        .expect("Failed to write mod.rs");
}

fn generate_pfn_types(file_path: &PathBuf) {
    let content = fs::read_to_string(file_path)
        .expect("Failed to read generated file");

    let fn_regex = Regex::new(
        r#"unsafe extern "C" \{\s*pub fn ([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*((?:[^)]*\n?)*?)\s*\)\s*->\s*([^;{]+);"#
    ).unwrap();

    let mut pfn_types = Vec::new();

    for cap in fn_regex.captures_iter(&content) {
        let fn_name = &cap[1];
        let params = cap[2].trim().replace('\n', " ").replace("  ", " ");
        let return_type = cap[3].trim();

        if params.contains("&self") || params.contains("&mut self") {
            continue;
        }

        let pfn_type = format!(
            "pub type PFN_{fn_name} = unsafe extern \"C\" fn({params}) -> {return_type};"
        );
        pfn_types.push(pfn_type);
    }

    if !pfn_types.is_empty() {
        let mut updated_content = content;
        updated_content.push_str("\n// Generated PFN types\n");
        for pfn_type in pfn_types {
            updated_content.push_str(&format!("{pfn_type}\n"));
        }

        fs::write(file_path, updated_content)
            .expect("Failed to write updated file");
    }
}
