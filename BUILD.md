# Build instructions

## Requirements

- Windows x64. The original development host was Windows 10.
- Python 3.13 x64 with the pinned dependencies in `requirements.txt`.
- Visual Studio C++ x64 build tools, including the Windows SDK and an x64 Developer Command Prompt. The local verification uses MSVC 14.51.36231 from Visual Studio 18 Community.
- The reviewer's legally obtained, **unmodified** Steam build 23447986 main executable: `End\Binaries\Win64\ff7rebirth_.exe`.
- Approximately 2 GB of free disk space and several GB of RAM. Generation can take several minutes. Avoid running the game during the build.

Required original SHA-256:
`752807180c4ed919667ff0ec163046410187e873888dd75248e78aaa72e363dc`

An installed mod executable is not a valid input. A verified original backup named `ff7rebirth_.exe.fxcompat-original` is acceptable; the driver copies it privately under the canonical original filename. No game is downloaded by these scripts.

## Full build

Extract a fresh copy of this tree. Open an **x64 Visual Studio Developer Command Prompt**, change to this source tree, and run:

```bat
py -3.13 -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe build.py --original "D:\YourLibrary\steamapps\common\FINAL FANTASY VII REBIRTH\End\Binaries\Win64\ff7rebirth_.exe"
```

Replace the example path with your original executable or original backup. Dependency installation needs internet access; the subsequent build itself does not. The build driver requires a fresh `build/` directory and refuses to overwrite a previous build. Use another fresh extraction for another run.

Steps performed, in order:

1. Check original hash and copy that input into `build/private/original/`.
2. Rebuild the modified PE from the frozen RVAs and lowering source.
3. Require an exact match to the released v6 target hash; require no skipped instructions or unwind refusals.
4. Compile `fxcompat_static.cpp` using `/O2 /MT /GS /guard:cf /LD`.
5. Generate and stream-verify `ff7rebirth.fxpatch`; require the released delta hash.
6. Copy the installer source into `build/native/` and update **only** its runtime/payload SHA-256 pins to the components just built. The generated source remains available for review. Production integrity checks stay enabled; no fixture/test macro is defined.
7. Compile the installer with `/O2 /MT /EHsc /GS /guard:cf /std:c++17`, linking bcrypt and advapi32.
8. Run only the installer's `--help`, and record hashes in `build/BUILD-RESULT.json`. No installer action or game launch occurs.

Review outputs are under `build/package/`. Do not distribute these as the quarantined release's original binaries: a compiler or linker timestamp can change EXE/DLL hashes. Runtime hash pins in the rebuilt installer intentionally match the rebuilt DLL. The original published source keeps the original release pins.

To verify only the game patch/delta without a C++ compiler, after installing the Python dependencies in a fresh source tree:

```bat
.venv\Scripts\python.exe build.py --original "D:\path\to\original\ff7rebirth_.exe" --patch-only
```

## Exact game/delta reproduction targets

- Rebuilt game: `65469807e5cf6d2a0b63e8fa92439fcb633fd30490798f38edfbc8f72c9800dc`
- Delta: `60322bd23e7cce896ed5119b35bfa59b38838fa731a6d6b220edd37825db1e8a`

Original published native binaries:

- `fxcompat.dll`: `f5f358973bc95b166fde14f5787d611e64790f0bd0361342926045254e4dea73`
- `FxCompatInstaller.exe`: `f89512c249103de0e07cce085cc757c6ef8f0366d7b2dab2ab2a016cb7a977de`
- Public candidate ZIP: `dde43a190ff52a9ff231fea1516b8d23f703bd94674f25a2ef1d00d3711366b2`

Reviewing the generated source and behavior remains necessary. Matching game/delta hashes establishes reproduction of those components, not proof that every possible game path is correct or that a third-party scanner will accept the release.
