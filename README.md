# Rebirth FX-8350 CPU Compatibility Patch (Experimental)

An experimental native CPU compatibility patch for **FINAL FANTASY VII REBIRTH, Steam build 23447986**. It replaces selected AVX2/BMI2 instructions with sequences that run on CPUs without AVX2, such as the AMD FX-8350, and adds a small local runtime for short instruction sites.

- **Download:** [Nexus Mods](https://www.nexusmods.com/finalfantasy7rebirth/mods/2477)
- **Works only on Steam build 23447986.** The installer checks the game executable's hash and refuses any other build, so a game update stops it from installing until the patch is regenerated.
- **Status:** experimental, gameplay-tested on one FX-8350 + RX 6600 PC. See *Testing and limitations* below.
- **License:** MIT (see [LICENSE](LICENSE)). No rights to the game itself are granted.

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

The runtime is loaded through the added PE import. Its exception handler redirects only registered illegal-instruction addresses in the same process to generated replacement stubs. It does not inject into unrelated processes. Optional developer diagnostics can write one unmatched-fault record to an explicitly inherited `FXCOMPAT_LOG_HANDLE`; normal use does not set this variable. No diagnostic upload is performed.

The patch changes a CPU-requirement branch for this exact build. It does not globally spoof CPUID or remove Steam ownership requirements. The original game hash is checked before any generation or installation.

## Testing and limitations

Only one FX-8350/RX 6600 computer has been gameplay-tested. The user reports playable combat with minor delays and clear in-game audio; in-game menus still crackle. The entire campaign and other PCs are untested. Some exception/fault semantics of generated replacements are not fully transparent. See the original release's TESTING.md for historical scope. A source build check is not an additional gameplay test.

OpenAI Codex generated most project code and documentation with iterative local tests and user gameplay feedback. No AI service is needed by the installed mod. iced-x86 and pefile are external development dependencies, installed separately under their respective licenses. This project is licensed under the MIT License (see LICENSE). No rights to the original game are granted.

Keep `build/` private: it contains full original/modified game executables and local paths. Publish only this source tree's tracked source/documents. Do not upload an entire development workspace or override `.gitignore` to add generated files.
