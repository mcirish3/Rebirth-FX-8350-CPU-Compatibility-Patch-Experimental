"""FX Reborn patcher: builds the AVX2/BMI2 compatibility patch on the player's own PC.

Instead of shipping a binary diff that only fits one exact game build, this
rebuilds the patch from whatever ff7rebirth_.exe Steam has installed:

  1. Finds the game (Steam libraries) and checks the CPU.
  2. Works out the untouched original: the current exe if it is unpatched (a
     fresh install or a Steam update), otherwise the saved backup.
  3. Picks the instructions to translate:
       - known build (Steam 23447986): the frozen, play-tested v6 list;
       - any other build: scans the exe (find_sites.py) -- "unverified build";
       - plus any "learned" sites fxcompat.dll logged as missed in earlier runs.
  4. Builds the patched exe, writes it next to the game, keeps the original as
     ff7rebirth_.exe.fxcompat-original, and records what it did in
     fxreborn-state.json.

After a Steam update just run it again: it sees the new unpatched exe, backs it
up, and rebuilds. Usage:

  py fxreborn.py install [path\\to\\ff7rebirth_.exe] [--rebuild]
  py fxreborn.py restore [path\\to\\ff7rebirth_.exe]
  py fxreborn.py status  [path\\to\\ff7rebirth_.exe]
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
sys.path[:0] = [str(SRC / "pylibs"), str(SRC)]

GAME_DIR = "FINAL FANTASY VII REBIRTH"
EXE_NAME = "ff7rebirth_.exe"
BACKUP_SUFFIX = ".fxcompat-original"
STATE_NAME = "fxreborn-state.json"
MISSED_LOG = "fxreborn-missed.log"
RUNTIME = "fxcompat.dll"
VERSION = "FX Reborn 0.7 (build-on-PC)"


class Stop(Exception):
    pass


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def is_patched(path: Path) -> bool:
    # Read only the headers: a pefile object on the path keeps the file mapped
    # (and locked against replacement) until garbage collection.
    import pefile
    with path.open("rb") as f:
        head = f.read(0x2000)
    pe = pefile.PE(data=head, fast_load=True)
    return any(s.Name.rstrip(b"\0") == b".fxcpt" for s in pe.sections)


# ---------------------------------------------------------------- CPU check
def cpu_features() -> dict:
    """CPUID via a tiny machine-code stub (Windows x64 calling convention)."""
    code = bytes.fromhex(
        "53"            # push rbx
        "4989d0"        # mov r8, rdx      (out pointer)
        "89c8"          # mov eax, ecx     (leaf)
        "31c9"          # xor ecx, ecx     (subleaf 0)
        "0fa2"          # cpuid
        "418900"        # mov [r8], eax
        "41895804"      # mov [r8+4], ebx
        "41894808"      # mov [r8+8], ecx
        "4189500c"      # mov [r8+12], edx
        "5b"            # pop rbx
        "c3")           # ret
    k32 = ctypes.windll.kernel32
    k32.VirtualAlloc.restype = ctypes.c_void_p
    k32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_uint32]
    mem = k32.VirtualAlloc(None, len(code), 0x3000, 0x40)
    ctypes.memmove(mem, code, len(code))
    fn = ctypes.CFUNCTYPE(None, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32 * 4))(mem)

    def cpuid(leaf):
        out = (ctypes.c_uint32 * 4)()
        fn(leaf, ctypes.byref(out))
        return list(out)
    _, _, c1, _ = cpuid(1)
    _, b7, _, _ = cpuid(7)
    _, _, ce, _ = cpuid(0x80000001)
    return {"AVX": bool(c1 >> 28 & 1), "FMA3": bool(c1 >> 12 & 1), "F16C": bool(c1 >> 29 & 1),
            "BMI1": bool(b7 >> 3 & 1), "LZCNT": bool(ce >> 5 & 1),
            "AVX2": bool(b7 >> 5 & 1), "BMI2": bool(b7 >> 8 & 1)}


def check_cpu():
    f = cpu_features()
    missing = [k for k in ("AVX", "FMA3", "F16C", "BMI1", "LZCNT") if not f[k]]
    if missing:
        raise Stop("This CPU lacks " + ", ".join(missing) + "; the patch needs at least an "
                   "AMD Piledriver-class CPU (FX-83xx/63xx/43xx, Kaveri/Carrizo APUs).")
    if f["AVX2"] and f["BMI2"]:
        print("Note: this CPU already supports AVX2 and BMI2, so the game runs without this mod.")


# ----------------------------------------------------------- game discovery
def steam_libraries() -> list[Path]:
    roots = []
    try:
        import winreg
        for hive, key in ((winreg.HKEY_CURRENT_USER, r"Software\Valve\Steam"),
                          (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Valve\Steam")):
            try:
                with winreg.OpenKey(hive, key) as k:
                    for name in ("SteamPath", "InstallPath"):
                        try:
                            roots.append(Path(winreg.QueryValueEx(k, name)[0]))
                        except OSError:
                            pass
            except OSError:
                pass
    except ImportError:
        pass
    libs = []
    for root in roots:
        vdf = root / "steamapps" / "libraryfolders.vdf"
        if vdf.exists():
            libs += [Path(p.replace("\\\\", "\\")) for p in re.findall(r'"path"\s+"([^"]+)"', vdf.read_text(errors="ignore"))]
        libs.append(root)
    seen, out = set(), []
    for lib in libs:
        key = str(lib).lower()
        if key not in seen:
            seen.add(key)
            out.append(lib)
    return out


def find_game(explicit: str | None) -> Path:
    if explicit:
        p = Path(explicit)
        p = p / EXE_NAME if p.is_dir() else p
        if not p.exists():
            raise Stop(f"Not found: {p}")
        return p
    found = [lib / "steamapps" / "common" / GAME_DIR / "End" / "Binaries" / "Win64" / EXE_NAME
             for lib in steam_libraries()]
    found = [p for p in found if p.exists()]
    if not found:
        raise Stop("Could not find FINAL FANTASY VII REBIRTH in your Steam libraries. "
                   "Pass the path to End\\Binaries\\Win64\\ff7rebirth_.exe.")
    if len(found) > 1:
        raise Stop("Found more than one installation; pass the one to patch:\n  " + "\n  ".join(map(str, found)))
    return found[0]


def game_running() -> bool:
    out = subprocess.run(["tasklist", "/FI", f"IMAGENAME eq {EXE_NAME}", "/NH"],
                         capture_output=True, text=True).stdout
    return EXE_NAME.lower() in out.lower()


# --------------------------------------------------------------- the patch
def load_state(exe: Path) -> dict:
    p = exe.with_name(STATE_NAME)
    return json.loads(p.read_text()) if p.exists() else {}


def save_state(exe: Path, state: dict):
    p = exe.with_name(STATE_NAME)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2))
    os.replace(tmp, p)


def learned_sites(exe: Path, state: dict) -> list[int]:
    """Main-module addresses fxcompat.dll logged as unpatched AVX2/BMI2 faults."""
    learned = {int(x, 16) for x in state.get("learned_sites", [])}
    log = exe.with_name(MISSED_LOG)
    if log.exists():
        for line in log.read_text(errors="ignore").splitlines():
            try:
                e = json.loads(line)
            except ValueError:
                continue
            if int(e.get("main_module", "0x0"), 16) and e.get("rva"):
                learned.add(int(e["rva"], 16))
    return sorted(learned)


def choose_sites(original: Path, original_sha: str, extra: list[int], scan: bool = False) -> tuple[list[int], str, dict]:
    v6 = json.loads((SRC / "v6_sites.json").read_text())
    if original_sha == v6["original_sha256"] and not scan:
        sites, kind, report = [int(x, 16) for x in v6["sites"]], "verified (Steam build 23447986, v6 list)", {}
    else:
        cache = SRC / "code_cache" / f"{original_sha}.sites.json"
        if cache.exists():
            data = json.loads(cache.read_text())
        else:
            import find_sites
            import pefile
            print("Unknown game build: scanning the executable for AVX2/BMI2 code (about 3-5 minutes)...", flush=True)
            discovery = find_sites.discover(original)
            sites, report = find_sites.select(pefile.PE(str(original), fast_load=True), discovery)
            data = {"sites": [hex(s) for s in sites], "report": report}
            cache.parent.mkdir(exist_ok=True)
            cache.write_text(json.dumps(data))
        sites, kind, report = [int(x, 16) for x in data["sites"]], "UNVERIFIED (scanned on this PC)", data["report"]
    added = sorted(set(extra) - set(sites))
    return sorted(set(sites) | set(extra)), kind, {**report, "learned_added": [hex(a) for a in added]}


def build(original: Path, sites: list[int], out_dir: Path) -> tuple[Path, dict]:
    import build_static_mod as engine
    engine.STAGING = out_dir
    builder = engine.Builder(original, [{"rva": hex(r)} for r in sites])
    builder.finish()
    exe = out_dir / original.name
    manifest = json.loads((out_dir / (original.name + ".manifest.json")).read_text())
    manifest["cpu_gate_rva"] = hex(builder.cpu_gate_rva)
    return exe, manifest


def install(exe: Path, rebuild: bool, scan: bool = False):
    check_cpu()
    if game_running():
        raise Stop("The game is running. Close it first.")
    backup = exe.with_name(EXE_NAME + BACKUP_SUFFIX)
    state = load_state(exe)
    current_sha = sha256(exe)

    if is_patched(exe):
        if not backup.exists() or is_patched(backup):
            raise Stop("The game exe is already patched but no clean backup was found. "
                       "Use Steam > Properties > Installed Files > Verify integrity, then run this again.")
        original_sha = sha256(backup)
        learned = learned_sites(exe, state)
        new_learned = set(learned) - {int(x, 16) for x in state.get("learned_sites", [])}
        if state.get("patched_sha256") == current_sha and not rebuild and not new_learned:
            print(f"Already installed for this game version ({state.get('site_kind')}). Nothing to do.")
            return
        print("Rebuilding from the saved original" + (" with newly learned sites." if new_learned else "."))
    else:
        # Unpatched exe: a fresh install, or Steam replaced it with an update.
        original_sha = current_sha
        if backup.exists() and sha256(backup) != current_sha:
            print("The game exe changed since the last patch (Steam update?). Saving the new original.")
            state = {}  # learned sites belong to the old build's addresses
        tmp = backup.with_suffix(".tmp")
        shutil.copy2(exe, tmp)
        if sha256(tmp) != current_sha:
            raise Stop("Backup copy failed verification. Nothing was changed.")
        os.replace(tmp, backup)
        learned = learned_sites(exe, state) if state.get("original_sha256") == original_sha else []

    runtime_src = ROOT / RUNTIME
    if not runtime_src.exists():
        raise Stop(f"{RUNTIME} is missing next to fxreborn.py.")

    sites, kind, report = choose_sites(backup, original_sha, learned, scan)
    print(f"Game build: {original_sha[:16]}...  sites: {len(sites)}  list: {kind}", flush=True)
    started = time.time()
    with tempfile.TemporaryDirectory(prefix="fxreborn-", dir=exe.parent) as tmpdir:
        work = Path(tmpdir)
        local = work / "original" / EXE_NAME
        local.parent.mkdir()
        shutil.copy2(backup, local)
        out = work / "out"
        out.mkdir()
        patched, manifest = build(local, sites, out)
        if manifest["unwind_refusals"]:
            raise Stop(f"{len(manifest['unwind_refusals'])} unwind refusals; not installing. Report this build.")
        if manifest["skipped"]:
            print(f"Warning: {len(manifest['skipped'])} instructions could not be translated "
                  "and are left as-is; if the game reaches them it will close.", flush=True)
        patched_sha = sha256(patched)
        shutil.copy2(runtime_src, exe.with_name(RUNTIME))
        os.replace(patched, exe)
    log = exe.with_name(MISSED_LOG)
    if log.exists():
        log.replace(log.with_suffix(".log.processed"))
    save_state(exe, {"tool": VERSION, "original_sha256": original_sha, "patched_sha256": patched_sha,
                     "site_kind": kind, "sites": len(sites), "learned_sites": [hex(x) for x in learned],
                     "methods": manifest["methods"], "skipped": len(manifest["skipped"]),
                     "cpu_gate_rva": manifest["cpu_gate_rva"], "scan_report": report,
                     "built": time.strftime("%Y-%m-%d %H:%M:%S")})
    print(f"Installed in {time.time() - started:.0f}s. Patched exe SHA-256 {patched_sha}")
    if not kind.startswith("verified"):
        print("This game version has not been play-tested with FX Reborn. If the game closes with a\n"
              "missing-instruction error, just run this patcher again: it learns the address from\n"
              f"{MISSED_LOG} and adds it. Please report unverified builds that work or fail.")


def restore(exe: Path):
    if game_running():
        raise Stop("The game is running. Close it first.")
    backup = exe.with_name(EXE_NAME + BACKUP_SUFFIX)
    if not is_patched(exe):
        print("The game exe is not patched. Nothing to restore.")
        return
    if not backup.exists() or is_patched(backup):
        raise Stop("No clean backup found. Use Steam's Verify integrity of game files instead.")
    tmp = exe.with_suffix(".restore.tmp")
    shutil.copy2(backup, tmp)
    os.replace(tmp, exe)
    for name in (RUNTIME, STATE_NAME):
        p = exe.with_name(name)
        if p.exists():
            p.unlink()
    print("Original game exe restored.")


def status(exe: Path):
    state = load_state(exe)
    print(f"Game: {exe}")
    print(f"Patched: {is_patched(exe)}")
    for k in ("tool", "site_kind", "sites", "skipped", "built", "original_sha256", "patched_sha256"):
        if k in state:
            print(f"  {k}: {state[k]}")
    if state and state.get("patched_sha256") != sha256(exe):
        print("  The exe differs from what FX Reborn installed (Steam update?). Run install again.")
    log = exe.with_name(MISSED_LOG)
    if log.exists():
        print(f"  {MISSED_LOG} has entries: run install again to add them.")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["install", "restore", "status"])
    ap.add_argument("exe", nargs="?", help="path to ff7rebirth_.exe (default: find it via Steam)")
    ap.add_argument("--rebuild", action="store_true", help="rebuild even if already installed")
    ap.add_argument("--scan", action="store_true",
                    help="scan the exe even for the known build (testing; normally only unknown builds are scanned)")
    a = ap.parse_args()
    print(VERSION)
    try:
        exe = find_game(a.exe)
        {"install": lambda: install(exe, a.rebuild, a.scan), "restore": lambda: restore(exe),
         "status": lambda: status(exe)}[a.command]()
    except Stop as e:
        print("Stopped:", e)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
