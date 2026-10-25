"""Build virtual API reference pages from the generated stubs, without importing br3k."""

import ast
from pathlib import Path

from mkdocs.config.defaults import MkDocsConfig
from mkdocs.exceptions import PluginError
from mkdocs.structure.files import File, Files


def public_names(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "__all__" for target in node.targets):
            names = ast.literal_eval(node.value)
            if isinstance(names, list) and all(isinstance(name, str) for name in names):
                return names
    raise PluginError(f"{path}: expected a literal __all__ list; regenerate stubs with cargo api")


def on_files(files: Files, *, config: MkDocsConfig) -> Files:
    stubs = Path(__file__).resolve().parents[2] / "stubs" / "br3k"
    modules: dict[str, Path] = {}
    for path in sorted(stubs.rglob("*.pyi")):
        parts = ("br3k", *path.relative_to(stubs).with_suffix("").parts)
        module = ".".join(parts[:-1] if path.stem == "__init__" else parts)
        modules[module] = path
    if "br3k" not in modules:
        raise PluginError("Missing br3k stubs; generate them with cargo api")

    for module, path in modules.items():
        names = public_names(path)
        domains = [name for name in names if f"{module}.{name}" in modules]
        members = [name for name in names if name not in domains]
        lines = [f"# {module}", ""]
        if domains:
            lines.extend(["## Feature Namespaces", ""])
            for name in domains:
                target = f"{name}/index.md" if modules[f"{module}.{name}"].stem == "__init__" else f"{name}.md"
                lines.append(f"- [{name}]({target})")
            lines.append("")
        lines.extend([f"::: {module}", "    options:", "      heading_level: 2",
            "      show_root_heading: false", "      show_root_toc_entry: false"])
        if members:
            lines.append("      members:")
            lines.extend(f"        - {name}" for name in members)
        else:
            lines.append("      members: []")
        relative = path.relative_to(stubs).with_suffix(".md")
        if path.stem == "__init__":
            relative = relative.with_name("index.md")
        files.append(File.generated(config, f"api/{relative.as_posix()}", content="\n".join(lines) + "\n"))
    return files
