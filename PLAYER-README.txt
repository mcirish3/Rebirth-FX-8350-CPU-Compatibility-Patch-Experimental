FX Reborn 0.7.2 - FINAL FANTASY VII REBIRTH on CPUs without AVX2
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

IF THE GAME WON'T START AFTER INSTALLING 0.7.0
  0.7.0 could leave the patched exe readable only by administrators, so Steam
  failed to start it ("CreateProcess returned 5" / access denied). Run
  "FX Reborn - Install or Update.cmd" from 0.7.1 or newer once: it repairs the
  permissions without rebuilding.

IF THE GAME FREEZES ON A LOADING SCREEN OR AFTER A CUTSCENE (audio keeps playing)
  This happens on 6-core FX CPUs such as the FX-6300. The game reads the CPU as
  3 cores and starts too few worker threads, which then wait on each other
  during level loads and quest updates. It isn't caused by the patch. Fix: in
  Steam, right-click the game > Properties > Launch Options and enter
      -usehyperthreading -USEALLAVAILABLECORES
  If it still freezes, try adding -NumWorkerThreads=4. Found and tested by
  domhan1234 (realdomdom on GitHub), who also noticed less audio stutter in
  the pause menu with it. Other FX CPUs may benefit too.

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
