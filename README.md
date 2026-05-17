# br3k

**br3k** is a mini-framework for Windows pentesting, designed to implement non-standard scenarios and combine interesting methods.

Its core provides many options to vary the pentest flow: select strategies to open a target process, read/write its memory, use different low-level API variants, and so on.

There are many well-known pentest techniques (process injection, payload delivery between targets) and other scripts implemented (see [scripts](docs/scripts.md) notes).

Some features are briefly documented in [core](docs/core.md) notes.

## Usage Notice

Use this project only for authorized, non-malicious education, research, and testing.

## Usage

The tool consists of two parts:

1. **Core**: an `.exe`/`.dll` binary with low-level Windows code and a built-in Python interpreter. At runtime it provides the `br3k` Python module.
2. **Scripts**: Python scripts that use the `br3k` module API to implement concrete techniques and test scenarios.

## Notes

### br3k is not Frida

br3k is similar in spirit to [Frida](https://frida.re/docs/home/): both are scriptable, process-oriented, and useful for research workflows where a high-level script drives low-level native operations. Both projects allow the operator to inject payloads or scripts into different targets, trace their internals, play with process code and shellcode, and use script primitives to implement complex test scenarios.

Frida is a broad, mature, cross-platform instrumentation framework, whereas br3k is a narrower Windows-focused research framework. br3k is more internals-heavy and more oriented toward experimenting with less common primitives, keeping many low-level choices visible: strategies to open a process, read/write process memory, use different low-level API variants, and so on.

Also, everybody loves Python more than JavaScript :)

### Why Rust

Originally prototyped in [C/C++](https://github.com/1ndahous3/br3k/tree/cpp), this project was later rewritten in Rust because:

- Cargo provides many libraries, avoiding git submodules or copying header-only helpers.
- `build.rs` allows flexible code generation and custom build logic without CMake hacks and external scripts.
- [RustPython](https://github.com/RustPython/RustPython) allows easy embedding of a Python VM, unlike [CPython](https://github.com/python/cpython), which is extremely hard to statically compile with frozen stdlib modules.
- Rust reflection simplifies generating code for various structs.

The project uses unsafe code extensively, so Rust is chosen for convenience and tooling rather than memory safety.

### Acknowledgments

- [Process Hacker (phnt)](https://github.com/processhacker/phnt)
- [Mimikatz](https://github.com/gentilkiwi/mimikatz)
- [Hasherezade's repositories](https://github.com/hasherezade?tab=repositories)
- [Awesome Injection](https://github.com/itaymigdal/awesome-injection)
