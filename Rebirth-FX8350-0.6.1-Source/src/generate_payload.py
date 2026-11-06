"""Create and verify an FXPATCH1 local delta without modifying either input.

No game is launched or installed. On Windows input handles deny writes/deletes
for the duration of generation, so the original and candidate remain stable.
"""
from __future__ import annotations
import argparse, ctypes, hashlib, json, mmap, os, struct, tempfile
from pathlib import Path

HEADER=struct.Struct('<8sQQ32s32sI')
HUNK=struct.Struct('<QI')
CHUNK=1024*1024
RUNTIME_SHA256='F5F358973BC95B166FDE14F5787D611E64790F0BD0361342926045254E4DEA73'

def open_locked(path: Path):
    if os.name!='nt':return path.open('rb')
    import ctypes.wintypes as w, msvcrt
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.CreateFileW.argtypes=[w.LPCWSTR,w.DWORD,w.DWORD,ctypes.c_void_p,w.DWORD,w.DWORD,w.HANDLE]
    kernel.CreateFileW.restype=w.HANDLE
    kernel.CloseHandle.argtypes=[w.HANDLE]
    handle=kernel.CreateFileW(str(path),0x80000000,1,None,3,0x08000080,None)
    if handle==ctypes.c_void_p(-1).value:raise ctypes.WinError(ctypes.get_last_error())
    try:descriptor=msvcrt.open_osfhandle(handle,os.O_RDONLY|os.O_BINARY)
    except BaseException:kernel.CloseHandle(handle);raise
    return os.fdopen(descriptor,'rb',buffering=0)

def digest_map(data):
    digest=hashlib.sha256()
    for start in range(0,len(data),CHUNK):digest.update(data[start:start+CHUNK])
    return digest.digest()

def changed_spans(original,candidate,merge_gap=12):
    spans=[]
    def add(start,end):
        if spans and start-spans[-1][1]<=merge_gap:spans[-1]=(spans[-1][0],end)
        else:spans.append((start,end))
    common=min(len(original),len(candidate))
    for page in range(0,common,16384):
        page_end=min(page+16384,common)
        if original[page:page_end]==candidate[page:page_end]:continue
        for block in range(page,page_end,64):
            block_end=min(block+64,page_end)
            before=original[block:block_end];after=candidate[block:block_end]
            if before==after:continue
            index=0
            while index<len(after):
                if before[index]==after[index]:index+=1;continue
                start=index
                while index<len(after) and before[index]!=after[index]:index+=1
                add(block+start,block+index)
    if len(candidate)>common:add(common,len(candidate))
    return spans

def read_exact(stream,length):
    value=stream.read(length)
    if len(value)!=length:raise ValueError('Truncated payload')
    return value

def verify_payload(path: Path,original,expected_original: bytes,expected_target: bytes):
    """Hash the reconstructed output by streaming original gaps and new hunks."""
    with path.open('rb') as stream:
        magic,original_size,target_size,original_hash,target_hash,count=HEADER.unpack(read_exact(stream,HEADER.size))
        if magic!=b'FXPATCH1' or original_size!=len(original) or original_hash!=expected_original or target_hash!=expected_target:
            raise ValueError('Payload header differs from the locked inputs')
        digest=hashlib.sha256();cursor=0
        def old_gap(start,end):
            if end>target_size:raise ValueError('Output gap exceeds target')
            while start<end:
                stop=min(start+CHUNK,end)
                if start<len(original):
                    present=min(stop,len(original));digest.update(original[start:present])
                    if present<stop:digest.update(bytes(stop-present))
                else:digest.update(bytes(stop-start))
                start=stop
        for _ in range(count):
            offset,length=HUNK.unpack(read_exact(stream,HUNK.size))
            if not length or offset<cursor or offset+length>target_size:raise ValueError('Invalid hunk range')
            old_gap(cursor,offset)
            remaining=length
            while remaining:
                chunk=read_exact(stream,min(remaining,CHUNK));digest.update(chunk);remaining-=len(chunk)
            cursor=offset+length
        old_gap(cursor,target_size)
        if stream.read(1):raise ValueError('Unexpected trailing payload data')
        if digest.digest()!=expected_target:raise ValueError('Reconstructed output SHA-256 mismatch')

def generate(original_path: Path,candidate_path: Path,output: Path,manifest: Path|None=None,
             candidate_manifest: Path|None=None,force=False):
    original_path=original_path.resolve(strict=True);candidate_path=candidate_path.resolve(strict=True)
    output=output.absolute();manifest=(manifest or output.with_suffix(output.suffix+'.json')).absolute()
    if original_path==candidate_path:raise ValueError('Original and candidate must be distinct files')
    destinations=[output.resolve(),manifest.resolve()]
    if len(set(destinations))!=2 or any(p in (original_path,candidate_path) for p in destinations):
        raise ValueError('Outputs must not overwrite either input or each other')
    for path in (output,manifest):
        if path.exists() and not force:raise FileExistsError(f'{path} exists; pass --force to replace this output')
        path.parent.mkdir(parents=True,exist_ok=True)
    builder=None
    if candidate_manifest:
        builder=json.loads(candidate_manifest.read_text(encoding='utf-8'))
        if builder.get('skipped'):raise ValueError('Builder manifest reports skipped instruction sites')
    temporary=None;temporary_manifest=None
    try:
        with open_locked(original_path) as before_file,open_locked(candidate_path) as after_file:
            before_size=os.fstat(before_file.fileno()).st_size;after_size=os.fstat(after_file.fileno()).st_size
            if not 0<before_size<=0xffffffff or not 0<after_size<=0xffffffff:raise ValueError('Input sizes are outside installer limits')
            with mmap.mmap(before_file.fileno(),0,access=mmap.ACCESS_READ) as before,mmap.mmap(after_file.fileno(),0,access=mmap.ACCESS_READ) as after:
                before_hash=digest_map(before);after_hash=digest_map(after)
                if before_hash==after_hash:raise ValueError('Candidate is identical to original')
                if builder:
                    if builder.get('source_sha256','').lower()!=before_hash.hex():raise ValueError('Builder source hash does not match original')
                    if builder.get('sha256','').lower()!=after_hash.hex():raise ValueError('Builder output hash does not match candidate')
                spans=changed_spans(before,after)
                if len(spans)>1000000:raise ValueError('Hunk count exceeds installer limit')
                descriptor,temp_name=tempfile.mkstemp(prefix='.fxpatch-',suffix='.tmp',dir=output.parent)
                temporary=Path(temp_name)
                digest=hashlib.sha256()
                with os.fdopen(descriptor,'wb') as stream:
                    def write(data):stream.write(data);digest.update(data)
                    write(HEADER.pack(b'FXPATCH1',before_size,after_size,before_hash,after_hash,len(spans)))
                    for start,end in spans:
                        write(HUNK.pack(start,end-start))
                        for pos in range(start,end,CHUNK):write(after[pos:min(pos+CHUNK,end)])
                    stream.flush();os.fsync(stream.fileno())
                verify_payload(temporary,before,before_hash,after_hash)
                report={
                    'schema_version':1,'format':'FXPATCH1','header_bytes':HEADER.size,
                    'original':{'path':str(original_path),'size':before_size,'sha256':before_hash.hex()},
                    'candidate':{'path':str(candidate_path),'size':after_size,'sha256':after_hash.hex()},
                    'payload':{'path':str(output),'size':temporary.stat().st_size,'sha256':digest.hexdigest(),'hunks':len(spans)},
                    'expected_runtime_sha256':RUNTIME_SHA256.lower(),
                    'candidate_manifest':str(candidate_manifest.resolve()) if candidate_manifest else None,
                    'reconstructed_output_hash_verified':True,
                    'installed_or_launched':False,
                }
        descriptor,temp_name=tempfile.mkstemp(prefix='.fxpatch-manifest-',suffix='.tmp',dir=manifest.parent)
        temporary_manifest=Path(temp_name)
        with os.fdopen(descriptor,'w',encoding='utf-8',newline='\n') as stream:
            json.dump(report,stream,indent=2);stream.write('\n');stream.flush();os.fsync(stream.fileno())
        os.replace(temporary,output);temporary=None
        os.replace(temporary_manifest,manifest);temporary_manifest=None
        return report
    finally:
        for path in (temporary,temporary_manifest):
            if path is not None:path.unlink(missing_ok=True)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('original',type=Path)
    parser.add_argument('candidate',type=Path)
    parser.add_argument('output',type=Path)
    parser.add_argument('--manifest',type=Path)
    parser.add_argument('--candidate-manifest',type=Path)
    parser.add_argument('--force',action='store_true')
    args=parser.parse_args()
    report=generate(args.original,args.candidate,args.output,args.manifest,args.candidate_manifest,args.force)
    print(json.dumps(report,indent=2))

if __name__=='__main__':main()
