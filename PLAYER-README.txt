FX Reborn 0.7.0 - FINAL FANTASY VII REBIRTH on CPUs without AVX2
==================================================================

Lets the Steam version of FF7 Rebirth run on CPUs that have AVX but not AVX2,
such as the AMD FX-8350, by replacing the game's AVX2/BMI2 instructions with
equivalents your CPU can run. On the test PC (FX-8350 + RX 6600) it went from
about 1 FPS under emulation to 30 FPS capped, and 45-85 FPS with the in-game
frame-rate limit turned off.

Needs: an AMD Piledriver-class CPU or newer (FX-83xx/63xx/43xx, Kaveri/Carrizo
APUs: AVX, FMA3, F16C, BMI1, LZCNT). Nothing else to install: this download
includes its own private copy of Python.

INSTALL
  1. Close the game.
  2. Unzip this folder anywhere (for example your Desktop).
  3. Double-click "FX Reborn - Install or Update.cmd" and accept the Windows
     administrator prompt. It finds the game through Steam, keeps a backup of
     the original exe, and builds the patch on your PC (about 2 minutes, or
     about 5 minutes for a game version it has not seen before).

AFTER A GAME UPDATE
  Steam replaces the game exe when the game updates, which removes the patch.
  Just run "FX Reborn - Install or Update.cmd" again. It notices the new
  version, saves it as the new backup, and rebuilds the patch for it.

  Game versions other than Steam build 23447986 are marked UNVERIFIED: the
  patch is built by scanning the exe, and nobody has play-tested that version
  yet. If the game closes with a missing-instruction error, run the installer
  again. The mod logs the exact address (fxreborn-missed.log in the game
  folder) and adds it on the next run. Please report what happened.

UNINSTALL
  Double-click "FX Reborn - Restore original.cmd", or use Steam > right-click
  the game > Properties > Installed Files > Verify integrity of game files.

TIPS
  - Turn the in-game frame-rate limit off: 30 FPS was a cap, not the CPU limit.
  - Short stutters during play are mostly the AMD driver compiling shaders.
    They get rarer as the shader cache fills. Leave AMD Software's shader
    cache on, and lower the graphics settings for fewer stutters.

WHAT IT CHANGES
  Only ff7rebirth_.exe (backed up as ff7rebirth_.exe.fxcompat-original) and
  three new files next to it: fxcompat.dll, fxreborn-state.json and, if needed,
  fxreborn-missed.log. No saves, settings, Steam files or other programs are
  touched, nothing is downloaded or uploaded, and CPUID is not spoofed.
  Source: https://github.com/mcirish3/Rebirth-FX-8350-CPU-Compatibility-Patch-Experimental

Experimental. Use at your own risk. MIT license (LICENSE). Python is included
under the Python Software Foundation License (python\LICENSE.txt); iced-x86
(MIT) and pefile (MIT) are included under their licenses (src\pylibs).
