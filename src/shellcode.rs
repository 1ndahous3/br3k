
pub fn shellcode_messageboxw() -> Vec<u8> {
    let shellcode = include_bytes!("shellcode_MessageBoxA.bin");
    let mut data = Vec::with_capacity(shellcode.len());
    data.extend_from_slice(shellcode);
    data
}
