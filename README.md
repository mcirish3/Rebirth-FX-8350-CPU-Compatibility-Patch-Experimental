# Rebirth FX-8350 CPU Compatibility Patch (Experimental)

An experimental native CPU compatibility patch for **FINAL FANTASY VII REBIRTH, Steam build 23447986**. It replaces selected AVX2/BMI2 instructions with sequences that run on CPUs without AVX2, such as the AMD FX-8350, and adds a small local runtime for short instruction sites.

- **Download:** [Nexus Mods](https://www.nexusmods.com/finalfantasy7rebirth/mods/2477)
- **The v6 release package works only on Steam build 23447986.** Its installer checks the game executable's hash. The new `fxreborn.py` patcher (below) builds the patch for whatever build is installed, so game updates are handled by running it again.
- **Status:** experimental, gameplay-tested on one FX-8350 + RX 6600 PC. See *Testing and limitations* below.
- **License:** MIT (see [LICENSE](LICENSE)). No rights to the game itself are granted.

---

## Game updates: build the patch on your own PC (`fxreborn.py`)

The v6 release ships a binary diff that fits only Steam build 23447986. `fxreborn.py` instead builds the patch from whatever `ff7rebirth_.exe` is installed, so a Steam update no longer breaks the mod. After an update, run it again.

- **Install or update:** `FX Reborn - Install or Update.cmd` (or `py -3.13 fxreborn.py install [path]`).
- **Restore the original:** `FX Reborn - Restore original.cmd` (or `py -3.13 fxreborn.py restore`).
- **Status:** `py -3.13 fxreborn.py status`.

How it works:

1. **Known build (23447986):** uses the frozen, play-tested v6 list. The result is byte-identical to the v6 release (SHA-256 `65469807…00dc`).
2. **Any other build:** scans the executable (`src/discover_code_sites.py` + `src/find_sites.py`). Instructions reached through direct control flow from the entry point, exports or unwind-table functions are always included. Pointer-reached code is included after an automatic version of the v6 manual review. Instructions found only by a byte sweep are never patched, because they may be data. On build 23447986 this scan selects exactly the 23,171 v6 sites and reproduces the v6 hash, without the saved list. Builds other than 23447986 are marked **unverified**, because nobody has play-tested them.
3. **CPU check:** found by its pattern (`src/cpu_gate.py`) rather than a fixed address.
4. **Safety net:** if the game reaches an AVX2/BMI2 instruction the scan missed, `fxcompat.dll` writes its address to `fxreborn-missed.log` next to the game before the game closes. The next `install` adds it ("learned sites").
5. The original is kept as `ff7rebirth_.exe.fxcompat-original`. When the exe changes underneath it (a Steam update), the new original is saved instead. State is kept in `fxreborn-state.json`.

The patcher currently needs Python 3.13 with `src/pylibs` (iced-x86 1.22.0, pefile 2024.8.26), plus a compiled `fxcompat.dll` next to `fxreborn.py`. A player release should bundle these. Building takes about 1.5 minutes for a known build, plus about 3 minutes of scanning for a new one.

---

## Source for security review

This tree contains the source of the v6 game patch and 0.6.1 portable installer, including the instruction lowering engines and the binary patch generator. It is intended for review of the quarantined public candidate, not as a new mod release. No game executable, game assets, save files or development recordings are included.

Start with [BUILD.md](BUILD.md). The full build creates a verified v6 game executable privately from the reviewer's own exact original executable, generates the binary delta, compiles the runtime DLL and installer, and keeps production component-hash verification enabled. It never installs the result or launches the game.

## Source map

- `src/bmi2_lower.py`, `avx2_lower.py`: native instruction replacements.
- `src/unwind_builder.py`: generated Windows x64 recovery metadata.
- `src/build_static_mod.py`: PE imports/sections, replacements, relocations, redirect map and metadata.
- `src/v6_sites.json`: the 23,171 selected original instruction RVAs and input/output hashes. It contains addresses, not a bundled original executable.
- `src/fxcompat_static.cpp`: in-process runtime and exact-address illegal-instruction redirection.
- `src/generate_payload.py`: binary delta generator and reconstruction verification.
- `src/fxcompat_installer.cpp`, `cpu_requirements.h`, `installer_portability.h`: installer, CPU policy, Steam discovery, verification and restoration.
- `src/*.cmd`: user entry points for the installer.
- `build.py`: explicit review build driver.

The copied PE builder has a portable input entry point: the development-only hardcoded game path and historical discovery CLI were removed. The build driver supplies the frozen v6 site inventory directly. Instruction generation and PE transformation logic were retained. This is not the separate v7 experiment.

## Review points

The installer reads Steam locations and modifies only the explicitly selected main executable and its compatibility DLL, retaining a hash-verified original backup. Unfamiliar executables, backups and component hashes are rejected. It does not modify saves/settings, alter permissions, request elevation, or make network requests.

The runtime is loaded through the added PE import. Its exception handler redirects only registered illegal-instruction addresses in the same process to generated replacement stubs. It does not inject into unrelated processes. When an illegal instruction is not in the table, it writes one record (address, instruction bytes, registers) to an explicitly inherited `FXCOMPAT_LOG_HANDLE` if one is set. Otherwise it appends the record to `fxreborn-missed.log` next to the game, and the game then closes as it would without the handler. The patcher reads that file to add missed sites. No diagnostic upload is performed.

The patch changes a CPU-requirement branch for this exact build. It does not globally spoof CPUID or remove Steam ownership requirements. The original game hash is checked before any generation or installation.

## Testing and limitations

Only one FX-8350/RX 6600 computer has been gameplay-tested. The user reports playable combat with minor delays and clear in-game audio; in-game menus still crackle. The entire campaign and other PCs are untested. Some exception/fault semantics of generated replacements are not fully transparent. See the original release's TESTING.md for historical scope. A source build check is not an additional gameplay test.

OpenAI Codex generated most project code and documentation with iterative local tests and user gameplay feedback. No AI service is needed by the installed mod. iced-x86 and pefile are external development dependencies, installed separately under their respective licenses. This project is licensed under the MIT License (see LICENSE). No rights to the original game are granted.

Keep `build/` private: it contains full original/modified game executables and local paths. Publish only this source tree's tracked source/documents. Do not upload an entire development workspace or override `.gitignore` to add generated files.
