"""Build the player download: FX Reborn with a private, portable Python.

Players should not need to install anything. This copies a minimal Python 3.13
runtime (the same layout as python.org's "embeddable" distribution: python.exe,
python313.dll, a zipped standard library and a ._pth file) from the local
Python install, adds the pinned libraries from src/pylibs, compiles
fxcompat.dll with MSVC, and zips it all.

Usage (from this folder):  py -3.13 package_release.py
Output: dist/FX-Reborn-<version>.zip
"""
from __future__ import annotations

import compileall
import hashlib
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VERSION = "0.7.1"
NAME = f"FX-Reborn-{VERSION}"
SRC_FILES = ["avx2_lower.py", "bmi2_lower.py", "build_static_mod.py", "unwind_builder.py",
             "cpu_gate.py", "find_sites.py", "discover_code_sites.py", "v6_sites.json"]
TOP_FILES = ["fxreborn.py", "LICENSE", "FX Reborn - Install or Update.cmd",
             "FX Reborn - Restore original.cmd", "FX Reborn - Status.cmd"]
STDLIB_SKIP = {"test", "idlelib", "tkinter", "turtledemo", "ensurepip", "venv", "lib2to3",
               "pydoc_data", "site-packages", "__pycache__", "unittest", "sqlite3", "curses", "dbm",
               "asyncio", "email", "http", "xml", "xmlrpc", "wsgiref", "multiprocessing",
               "concurrent", "html", "urllib", "zoneinfo", "tomllib", "_pyrepl"}
# Only the compiled modules the patcher uses (everything else it needs is built
# into python313.dll); keeps the download small and avoids shipping OpenSSL.
DLL_KEEP = {"_ctypes.pyd", "libffi-8.dll"}


def sha256(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def build_dll(out: Path):
    vswhere = Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / \
        "Microsoft Visual Studio" / "Installer" / "vswhere.exe"
    vcvars = None
    if vswhere.exists():
        inst = subprocess.run([str(vswhere), "-latest", "-products", "*", "-property", "installationPath"],
                              capture_output=True, text=True).stdout.strip()
        if inst:
            vcvars = Path(inst) / "VC" / "Auxiliary" / "Build" / "vcvars64.bat"
    if not vcvars or not vcvars.exists():
        sys.exit("Visual Studio C++ build tools not found (needed to compile fxcompat.dll).")
    work = ROOT / "dist" / "native"
    work.mkdir(parents=True, exist_ok=True)
    script = work / "build.cmd"
    script.write_text(f'@call "{vcvars}" >nul\r\ncd /d "{work}"\r\n'
                      f'cl /nologo /W4 /O2 /MT /GS /guard:cf /LD "{ROOT / "src" / "fxcompat_static.cpp"}" '
                      f'/link /out:fxcompat.dll /implib:fxcompat.lib /incremental:no\r\n')
    subprocess.run(["cmd", "/c", str(script)], check=True)
    shutil.copy2(work / "fxcompat.dll", out / "fxcompat.dll")


def build_python(out: Path):
    base = Path(sys.base_prefix)
    if sys.version_info[:2] != (3, 13):
        sys.exit("Run this with Python 3.13 (the bundled iced-x86 build is for 3.13).")
    py = out / "python"
    py.mkdir()
    for name in ("python.exe", "python3.dll", "python313.dll", "vcruntime140.dll",
                 "vcruntime140_1.dll", "LICENSE.txt"):
        shutil.copy2(base / name, py / name)
    for f in (base / "DLLs").iterdir():
        if f.name.lower() in DLL_KEEP:
            shutil.copy2(f, py / f.name)
    # Standard library as compiled bytecode in a zip, like the embeddable distribution.
    stage = ROOT / "dist" / "stdlib"
    if stage.exists():
        shutil.rmtree(stage)
    lib = base / "Lib"
    for path in lib.rglob("*.py"):
        rel = path.relative_to(lib)
        if rel.parts[0] in STDLIB_SKIP or "__pycache__" in rel.parts or "tests" in rel.parts:
            continue
        dest = stage / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, dest)
    # ddir: tracebacks show "python313.zip\threading.py", not the build PC's folder.
    compileall.compile_dir(str(stage), quiet=1, legacy=True, optimize=0, ddir="python313.zip")
    with zipfile.ZipFile(py / "python313.zip", "w", zipfile.ZIP_DEFLATED) as z:
        for f in stage.rglob("*.pyc"):
            z.write(f, f.relative_to(stage).as_posix())
    shutil.rmtree(stage)
    # ._pth: isolated, fixed search path (ignores any installed Python and PYTHONPATH).
    (py / "python313._pth").write_text("python313.zip\n.\n..\\src\\pylibs\n..\\src\n..\n")


def main():
    dist = ROOT / "dist"
    out = dist / NAME
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    for name in TOP_FILES:
        shutil.copy2(ROOT / name, out / name)
    shutil.copy2(ROOT / "PLAYER-README.txt", out / "README.txt")
    (out / "src").mkdir()
    for name in SRC_FILES:
        shutil.copy2(ROOT / "src" / name, out / "src" / name)
    shutil.copytree(ROOT / "src" / "pylibs", out / "src" / "pylibs",
                    ignore=shutil.ignore_patterns("__pycache__", "*.dist-info"))
    for info in (ROOT / "src" / "pylibs").glob("*.dist-info"):  # keep license files
        shutil.copytree(info, out / "src" / "pylibs" / info.name)
    build_dll(out)
    build_python(out)
    sums = [f"{sha256(f)}  {f.relative_to(out).as_posix()}" for f in sorted(out.rglob("*")) if f.is_file()]
    (out / "SHA256SUMS.txt").write_text("\n".join(sums) + "\n")
    archive = dist / f"{NAME}.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for f in sorted(out.rglob("*")):
            if f.is_file():
                z.write(f, (Path(NAME) / f.relative_to(out)).as_posix())
    print(f"{archive}  {archive.stat().st_size / 1e6:.1f} MB  sha256 {sha256(archive)}")


if __name__ == "__main__":
    main()
