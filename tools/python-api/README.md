# Python API Generation

`cargo api` collects the complete registered br3k API inventory and generates stubs from Rust declarations. `cargo api --check` checks the stubs without writing files. Run it before committing binding changes. Release generator tests also check for stale stubs.

The inventory covers the root module and every registered namespace: PE, processes, threads/thread pools, memory, files, PDBs, COM, br3k IPC, shellcode, system API configuration, transactions, resources, and YAML configuration. Source contracts document every exported class, enum variant, method, property, and function. `cargo api --coverage` reports declarations without source prose without writing files; a signature alone is not counted as prose.

## Source Of Truth

- RustPython `#[pyclass(module = ..., name = ...)]` supplies class identity.
- `#[pymethod]`, `#[pygetset]`, `#[pymember]`, `#[pyclassmethod]`, and `#[pyfunction]` supply exposure.
- Rust types and `#[pyarg]` fields supply signatures and argument modes.
- `///` comments supply class, method, property, and parameter documentation.
- `#[pyi(...)]` supplies only information erased by `PyObjectRef` or other adapters.
- The PE registration table and native `extend_module!`/enum registrations decide what is public.

There is no second override dictionary in the generator. It parses Rust syntax with `syn`, resolves local argument-record imports, validates registration/type references, and emits deterministic LF output. Unknown metadata keys and duplicate hints fail; ambiguous declarations require disambiguation, not a guessed type.

Class aliases are rendered as re-exports or same-module assignments, not duplicate definitions. Explicit `__all__` lists keep renamed exports visible to type checkers. Built-in annotation types are qualified when a class member shadows their names. Feature namespaces are preferred over root aliases, with the shortest exported name used within those namespaces. Classes declared with `module = false` retain their runtime metadata; generated import paths describe where they are exported, not a change to `__module__` or `__name__`. Root and namespaced non-PE enums are separate IntEnum objects created by the runtime and are documented separately, not as aliases.

## Concrete Returns

Prefer concrete RustPython payloads/references and `Option<T>`/`PyResult<T>`. The generator infers the Python class from its declaration or registration; ordinary return types do not need a separate string hint.

```rust
#[pyclass]
impl PeImage {
    /// Copy bytes in the image's declared storage layout.
    #[pygetset]
    fn data(zelf: &Py<Self>, vm: &VirtualMachine) -> PyRef<PyBytes> {
        vm.ctx.new_bytes(zelf.image.data().to_vec())
    }
}
```

Use the adapters re-exported by the VM prelude where RustPython erases information:

- `PyListOf<T>::new(Vec<T>, vm)` constructs a Python list from typed elements. Clones share the same Python list, including subsequent Python mutations. It never reads those mutable elements back as unchecked Rust `T` values.
- `PyEnumValue<E>::new(value, vm)` constructs the registered `IntEnum` from a Rust enum value and propagates lookup/construction errors. Its private object/marker fields cannot be used to label an arbitrary object with an unchecked type.
- RustPython's `Either<A, B>` represents return unions without a string override.

Enum registration and the conversion trait share the declarations in `lib/src/vm/py_pe/enums.rs`. The adapters are Rust-only conversion types, not new Python classes. Return `PyRef<T>` for an existing object to retain its identity.

Conversions are directional: RustPython returns `Vec<u8>` as `bytes`, whereas an input `Vec<u8>` accepts an iterable of integers (including Python bytes). A generic `Vec<T>` return is not a list conversion in this RustPython version; use `PyListOf<T>` instead.

## Escape Hatches

Place `#[py_api]` before an enclosing macro only when nested `#[pyi]` hints are needed. It validates/removes those hints, leaving registration and `///` comments to RustPython. Retain hints for genuinely erased or custom-converted arguments.

Direct readonly `#[pymember]` fields supply property names, types, and documentation. For a `PyListRef` field, use a hint such as `#[pyi(ty = "list[br3k.pe.headers.Section]")]` to retain the element type. Writable and nested-path members are not supported by the generator; keep using `#[pygetset]` for computed or converted properties.

Argument fields carry their own semantic type and documentation:

```rust
#[py_api]
#[derive(FromArgs)]
pub struct OptionsArgs {
    /// Auto balances declared-IAT recovery and bounded code analysis.
    #[pyi(ty = "br3k.pe.recovery.Strength")]
    #[pyarg(named, optional)]
    strength: OptionalArg<PyObjectRef>,
}
```

For a direct erased argument, use a method/function hint such as `#[pyi(params(target = "br3k.pe.Capture"))]`. Hints use Python type expressions: qualified names, `list[T]`, and `T | None`. They describe types; they do not change runtime conversions or validate target values.

## Documentation

The pinned RustPython version exposes Rust `///` comments on classes, methods, class methods, module functions, and property descriptors through `__doc__`. Standard Python tools such as `help()` and `pydoc` consume this metadata, but br3k currently disables RustPython's `host_env` feature: `pydoc` cannot import its native `nt` dependency in this embedded runtime. Read `__doc__` directly or use the generated reference. Its inferred `__text_signature__` is best-effort and cannot fully expand our `FromArgs` records. Use generated stubs/reference signatures for those APIs.

Both `#[pygetset]` getter comments and `#[pymember]` field comments are available on the class descriptor's `__doc__` and in generated stubs/reference. Inspect the descriptor on the class, not the property's value on an instance.

Write detailed contracts beside Rust declarations. Keep hand-written Markdown for workflow examples, architecture, and limitations. The generator embeds these contracts and parameter documentation from `FromArgs` in the stubs. During a documentation build, the MkDocs hook creates virtual namespace pages from the stubs and their `__all__` lists; mkdocstrings renders the API without importing br3k. No intermediate Markdown pages are written or tracked.

Upstream implementation: [class and member macros](https://github.com/RustPython/RustPython/blob/5bccf31156996d42882485ba70f17edbc77a713e/crates/derive-impl/src/pyclass.rs), [get/set descriptor](https://github.com/RustPython/RustPython/blob/5bccf31156996d42882485ba70f17edbc77a713e/crates/vm/src/builtins/getset.rs), [member descriptor](https://github.com/RustPython/RustPython/blob/5bccf31156996d42882485ba70f17edbc77a713e/crates/vm/src/builtins/descriptor.rs).

## Build Integration

Generation is an explicit Cargo target, not a side effect of a procedural macro or `lib/build.rs`. Ordinary builds never rewrite checked-in files. The generator does not link br3k, instantiate a Python VM, or need to run the target architecture. Its parser/renderer library can also be called from a future build script if an `OUT_DIR` artifact is needed.

Outputs are limited to `stubs/br3k/__init__.pyi`, `stubs/br3k/*.pyi`, and `stubs/br3k/pe/*.pyi`: signatures, source docstrings, and public exports for editors and documentation tooling.

The root uv project also packages these stubs as a PEP 561 `br3k-stubs` wheel, checks Python consumers with ty/prek, and builds the HTML reference. See [Development](../../docs/development.md) for commands, staging versions, and isolated installed-wheel validation. The tools run on CPython; the scripts still execute inside br3k's RustPython VM.

Checks cover metadata validation, import resolution, duplicate Rust short names, type inference, generated-file drift, Python syntax, and runtime registration. The runtime inventory test checks every namespace, class member, function, constant, and class alias, including undocumented extra exports. Prose coverage is enforced across the full API to prevent newly exposed members losing their contracts. Dynamic/external types without a declaration or hint remain `Any`; the tool is not a Rust compiler or a complete type checker.
