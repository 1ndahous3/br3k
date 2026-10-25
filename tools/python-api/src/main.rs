use br3k_python_api::{Error, collect, render};
use std::{env, fs, path::Path, result::Result};

fn run() -> Result<(), Error> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.iter().any(|arg| arg == "--help") {
        println!("cargo api [--check] [--coverage]\nGenerate all br3k stubs from Rust declarations. --check never writes files.\n--coverage lists declarations without source documentation and never writes files.");
        return Ok(());
    }
    if args.iter().any(|arg| !["--check", "--coverage"].contains(&arg.as_str())) { return Err("expected cargo api [--check] [--coverage]".into()); }
    let check = args.iter().any(|arg| arg == "--check");
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize()?;
    let api = collect::collect(&root)?;
    if args.iter().any(|arg| arg == "--coverage") {
        let mut missing = 0;
        for class in &api.classes {
            if class.doc.is_empty() { println!("{}:{} {}.{}", class.location.path, class.location.line, class.module, class.name); missing += 1; }
            for (name, doc) in &class.variants {
                if doc.is_empty() { println!("{}:{} {}.{}.{name}", class.location.path, class.location.line, class.module, class.name); missing += 1; }
            }
            for method in &class.methods {
                if method.doc.is_empty() { println!("{}:{} {}.{}.{}", method.location.path, method.location.line, class.module, class.name, method.name); missing += 1; }
            }
        }
        for (module, method) in &api.functions {
            if method.doc.is_empty() { println!("{}:{} {module}.{}", method.location.path, method.location.line, method.name); missing += 1; }
        }
        println!("{missing} declarations without source documentation");
        return Ok(());
    }
    let files = render::generate(&api)?;
    let mut changed = Vec::new();
    for (name, contents) in &files {
        let path = root.join(name);
        if fs::read_to_string(&path).is_ok_and(|old| old == *contents) { continue; }
        changed.push(name);
        if !check { fs::create_dir_all(path.parent().unwrap())?; fs::write(&path, contents)?; }
    }
    if check && !changed.is_empty() { return Err(format!("stale generated files (run cargo api):\n{}", changed.iter().map(|name| name.as_str()).collect::<Vec<_>>().join("\n")).into()); }
    println!("{} registered types; {} generated files; {} {}", api.classes.len(), files.len(), changed.len(), if check { "stale" } else { "updated" });
    Ok(())
}

fn main() {
    if let Err(error) = run() { eprintln!("Python API generation failed: {error}"); std::process::exit(1); }
}
