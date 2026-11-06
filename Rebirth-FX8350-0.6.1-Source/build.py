"""Review build for 0.6.1/v6. No installation, game launch or network requests.

Run in an x64 Visual Studio Developer Command Prompt using the documented Python
environment. A legally obtained, exact original executable must be supplied.
"""
from pathlib import Path
import argparse, hashlib, json, shutil, subprocess, sys

ROOT=Path(__file__).resolve().parent
SRC=ROOT/'src'
sys.path.insert(0,str(SRC))
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--original',required=True,type=Path)
    p.add_argument('--patch-only',action='store_true',help='Rebuild and verify game delta without invoking a compiler')
    a=p.parse_args()
    original=a.original.resolve()
    sites=json.loads((SRC/'v6_sites.json').read_text())
    if sha(original)!=sites['original_sha256']:raise ValueError('Unsupported original executable')
    if not a.patch_only and not shutil.which('cl'):raise RuntimeError('Use an x64 Visual Studio Developer Command Prompt')
    build=ROOT/'build'
    if build.exists():raise RuntimeError('build/ already exists; use a fresh extracted source tree for each build')
    private=build/'private'; private.mkdir(parents=True)
    input_dir=private/'original';input_dir.mkdir()
    local=input_dir/'ff7rebirth_.exe';shutil.copy2(original,local)
    import build_static_mod as engine
    engine.STAGING=private/'candidate';engine.STAGING.mkdir()
    engine.Builder(local,[{'rva':r} for r in sites['sites']]).finish()
    candidate=engine.STAGING/'ff7rebirth_.exe'
    if sha(candidate)!=sites['target_sha256']:raise RuntimeError('Rebuilt game patch differs from released v6')
    manifest=json.loads((engine.STAGING/'ff7rebirth_.exe.manifest.json').read_text())
    if manifest['skipped'] or manifest['unwind_refusals']:raise RuntimeError('Translation/unwind refusal')
    package=build/'package';package.mkdir()
    import generate_payload as delta
    runtime_hash=None
    if not a.patch_only:
        native=build/'native';native.mkdir()
        subprocess.run(['cl','/nologo','/W4','/O2','/MT','/GS','/guard:cf','/LD',str(SRC/'fxcompat_static.cpp'),
            '/link','/out:fxcompat.dll','/implib:fxcompat.lib','/incremental:no'],cwd=native,check=True)
        shutil.copy2(native/'fxcompat.dll',package/'fxcompat.dll')
        runtime_hash=sha(package/'fxcompat.dll')
        delta.RUNTIME_SHA256=runtime_hash.upper()
    payload=package/'ff7rebirth.fxpatch'
    delta.generate(local,candidate,payload,None,engine.STAGING/'ff7rebirth_.exe.manifest.json',False)
    payload_hash=sha(payload)
    if payload_hash!='60322bd23e7cce896ed5119b35bfa59b38838fa731a6d6b220edd37825db1e8a':
        raise RuntimeError('Rebuilt delta differs from released v6')
    if not a.patch_only:
        installer=(SRC/'fxcompat_installer.cpp').read_text()
        for label,value in [('RUNTIME_SHA256',runtime_hash),('PAYLOAD_SHA256',payload_hash)]:
            import re
            installer,count=re.subn(r'(static const char\* '+label+r'=")[0-9A-F]+(";)',lambda m:m[1]+value.upper()+m[2],installer)
            if count!=1:raise RuntimeError('Hash pin update did not match exactly once')
        (native/'fxcompat_installer.cpp').write_text(installer)
        for name in ('cpu_requirements.h','installer_portability.h'):shutil.copy2(SRC/name,native/name)
        subprocess.run(['cl','/nologo','/W4','/O2','/MT','/EHsc','/GS','/guard:cf','/std:c++17',
            'fxcompat_installer.cpp','/Fe:FxCompatInstaller.exe','/Fo:fxcompat_installer.obj',
            '/link','bcrypt.lib','advapi32.lib','/incremental:no'],cwd=native,check=True)
        shutil.copy2(native/'FxCompatInstaller.exe',package/'FxCompatInstaller.exe')
        for name in ('Install mod.cmd','Restore original.cmd','Verify installation.cmd','Check compatibility.cmd'):
            shutil.copy2(SRC/name,package/name)
        subprocess.run([str(package/'FxCompatInstaller.exe'),'--help'],check=True)
    result={'original_sha256':sha(original),'rebuilt_game_sha256':sha(candidate),'payload_sha256':payload_hash,
        'runtime_sha256':runtime_hash,'translated':manifest['translated'],'skips':len(manifest['skipped']),
        'unwind_refusals':len(manifest['unwind_refusals']),'full_native_build':not a.patch_only,
        'installed_or_launched_game':False,'binaries':{f.name:sha(f) for f in package.iterdir() if f.is_file()}}
    (build/'BUILD-RESULT.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
if __name__=='__main__':main()
