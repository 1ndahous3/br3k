// Harmless idle target for read-only PE tests.
use std::{env, fs, io, thread, time::{Duration, Instant}};
use windows_sys::Win32::System::LibraryLoader::LoadLibraryW;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let ready = match args.as_slice() {
        [mode, ready] if mode == "--idle" => ready,
        _ => return Err("usage: pe-target --idle <readiness-file>".into()),
    };
    // Keep a known import-rich DLL loaded even when Cargo links our CRT statically.
    let library = "ucrtbase.dll\0".encode_utf16().collect::<Vec<_>>();
    if unsafe { LoadLibraryW(library.as_ptr()) }.is_null() {
        return Err(io::Error::last_os_error().into());
    }
    fs::write(ready, std::process::id().to_string())?;
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(3600) {
        thread::sleep(Duration::from_millis(100));
    }
    Ok(())
}
