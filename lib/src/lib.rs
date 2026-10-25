mod prelude;
pub mod sysapi;
pub mod br3k_ipc;
mod str;
pub mod fs;
mod kdump;
mod pdb;
pub mod pe;
mod shellcode;

pub mod vm;
pub mod logging;

pub const BR3K_VERSION: &str = env!("BR3K_VERSION");

#[cfg(test)]
mod tests;
