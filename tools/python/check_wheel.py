"""Check distribution contents and type-check scenarios against the installed wheel only."""

import argparse
from email.parser import Parser
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import tomllib
import zipfile


def check_wheel(wheel: Path) -> None:
    root = Path(__file__).resolve().parents[2]
    source = root / "stubs" / "br3k"
    expected = {"br3k-stubs/" + path.relative_to(source).as_posix(): path.read_bytes() for path in source.rglob("*.pyi")}
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        actual = {name: archive.read(name) for name in names if name.endswith(".pyi")}
        if actual != expected:
            raise RuntimeError("Wheel stubs differ from the generated API")
        if any(not name.startswith("br3k-stubs/") and ".dist-info/" not in name for name in names):
            raise RuntimeError("Unexpected files in the stub-only wheel")
        if any(name.startswith("br3k-stubs/") and not name.endswith(".pyi") for name in names):
            raise RuntimeError("The stub package must contain only .pyi files")
        metadata = Parser().parsestr(archive.read(next(name for name in names if name.endswith(".dist-info/METADATA"))).decode())
        if metadata["Name"] != "br3k-stubs" or metadata.get_all("Requires-Dist"):
            raise RuntimeError("Unexpected package name or runtime dependencies")

    uv = shutil.which("uv")
    ty = shutil.which("ty")
    if uv is None or ty is None:
        raise RuntimeError("Run with uv run --locked python tools/python/check_wheel.py <wheel>")
    config = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["tool"]["ty"]["environment"]
    with tempfile.TemporaryDirectory(prefix="br3k-wheel-") as directory:
        isolated = Path(directory)
        environment = isolated / ".venv"
        subprocess.run([uv, "venv", str(environment), "--python", sys.executable], check=True, cwd=isolated)
        subprocess.run([uv, "pip", "install", "--python", str(environment), "--no-deps", str(wheel)], check=True, cwd=isolated)
        shutil.copytree(root / "scripts", isolated / "scripts", ignore=shutil.ignore_patterns("__pycache__"))
        shutil.copytree(root / "tests" / "vm", isolated / "tests" / "vm", ignore=shutil.ignore_patterns("__pycache__"))
        # Explicit empty config prevents discovering source stubs or parent-project settings.
        config_path = isolated / "ty.toml"
        config_path.write_text("", encoding="utf-8")
        command = [ty, "check", "--config-file", str(config_path), "--python", str(environment),
            "--python-version", config["python-version"], "--python-platform", config["python-platform"]]
        subprocess.run([*command, "scripts", "tests/vm"], check=True, cwd=isolated)
        probe = isolated / "invalid_api.py"
        probe.write_text("import br3k\nimage = br3k.pe.Image.from_file(123)\nimage.no_such_method()\n", encoding="utf-8")
        result = subprocess.run([*command, str(probe), "--output-format", "concise"], cwd=isolated, capture_output=True, text=True)
        diagnostics = result.stdout + result.stderr
        if result.returncode != 1 or not all(rule in diagnostics for rule in ("invalid-argument-type", "unresolved-attribute")):
            raise RuntimeError(f"Installed stubs did not reject invalid API use:\n{diagnostics}")
    print(f"Validated {wheel.name}: {len(expected)} stubs, scenario types, and invalid-API rejection")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheel", type=Path)
    check_wheel(parser.parse_args().wheel.resolve())
