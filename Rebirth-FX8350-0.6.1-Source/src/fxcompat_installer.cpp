#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#include <tlhelp32.h>
#include <stdint.h>
#include <array>
#include <vector>
#include <string>
#include <stdexcept>
#include <iostream>
#include <algorithm>
#include <filesystem>
#include <utility>
#include "cpu_requirements.h"
#pragma comment(lib,"bcrypt.lib")
#pragma comment(lib,"advapi32.lib")

namespace fs=std::filesystem;
using Digest=std::array<unsigned char,32>;
static const wchar_t* GAME_NAME=L"ff7rebirth_.exe";
static const wchar_t* BACKUP_NAME=L"ff7rebirth_.exe.fxcompat-original";
static const wchar_t* PAYLOAD_NAME=L"ff7rebirth.fxpatch";
static const wchar_t* RUNTIME_NAME=L"fxcompat.dll";
static const char* RUNTIME_SHA256="F5F358973BC95B166FDE14F5787D611E64790F0BD0361342926045254E4DEA73";
static const char* PAYLOAD_SHA256="60322BD23E7CCE896ED5119B35BFA59B38838FA731A6D6B220EDD37825DB1E8A";

#pragma pack(push,1)
struct PatchHeader {
    char magic[8];
    uint64_t original_size;
    uint64_t target_size;
    unsigned char original_hash[32];
    unsigned char target_hash[32];
    uint32_t hunk_count;
};
struct HunkHeader { uint64_t offset; uint32_t length; };
#pragma pack(pop)
static_assert(sizeof(PatchHeader)==92,"Patch header layout mismatch");
static_assert(sizeof(HunkHeader)==12,"Hunk header layout mismatch");

static void Fail(const std::string& text) { throw std::runtime_error(text); }
static void WinFail(const char* operation) { Fail(std::string(operation)+" (Windows error "+std::to_string(GetLastError())+")"); }
struct File {
    HANDLE h=INVALID_HANDLE_VALUE;
    File()=default;
    explicit File(HANDLE handle):h(handle){}
    File(const File&)=delete;
    File& operator=(const File&)=delete;
    File(File&& other) noexcept:h(std::exchange(other.h,INVALID_HANDLE_VALUE)){}
    File& operator=(File&& other) noexcept { if(this!=&other){close();h=std::exchange(other.h,INVALID_HANDLE_VALUE);}return *this; }
    ~File(){close();}
    void close(){if(h!=INVALID_HANDLE_VALUE){CloseHandle(h);h=INVALID_HANDLE_VALUE;}}
};
struct Temp {
    fs::path path;
    bool active=true;
    Temp(fs::path p):path(std::move(p)){}
    Temp(const Temp&)=delete;
    Temp& operator=(const Temp&)=delete;
    Temp(Temp&& other) noexcept:path(std::move(other.path)),active(std::exchange(other.active,false)){}
    ~Temp(){if(active&&!path.empty())DeleteFileW(path.c_str());}
};
static bool Exists(const fs::path& path) {
    DWORD attr=GetFileAttributesW(path.c_str());
    if(attr!=INVALID_FILE_ATTRIBUTES){if(attr&FILE_ATTRIBUTE_DIRECTORY)Fail("An expected file is a directory.");return true;}
    DWORD e=GetLastError();if(e==ERROR_FILE_NOT_FOUND||e==ERROR_PATH_NOT_FOUND)return false;
    SetLastError(e);WinFail("Cannot inspect file");return false;
}
static File ReadFileHandle(const fs::path& path) {
    // Deny write/delete while this handle is used for verification or staging.
    HANDLE h=CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(h==INVALID_HANDLE_VALUE)WinFail("Cannot open file for verification");
    return File(h);
}
static uint64_t Size(HANDLE file) {
    LARGE_INTEGER value={};if(!GetFileSizeEx(file,&value))WinFail("Cannot read file size");
    if(value.QuadPart<0)Fail("Invalid file size.");return static_cast<uint64_t>(value.QuadPart);
}
static void Seek(HANDLE file,uint64_t offset) {
    LARGE_INTEGER position;position.QuadPart=static_cast<LONGLONG>(offset);
    if(!SetFilePointerEx(file,position,nullptr,FILE_BEGIN))WinFail("Cannot seek file");
}
static void ReadExact(HANDLE file,void* data,DWORD length) {
    unsigned char* cursor=static_cast<unsigned char*>(data);
    while(length){DWORD got=0;if(!ReadFile(file,cursor,length,&got,nullptr))WinFail("Cannot read file");if(!got)Fail("Patch file is truncated.");cursor+=got;length-=got;}
}
static void WriteExact(HANDLE file,const void* data,DWORD length) {
    const unsigned char* cursor=static_cast<const unsigned char*>(data);
    while(length){DWORD written=0;if(!WriteFile(file,cursor,length,&written,nullptr))WinFail("Cannot write staged file");if(!written)Fail("Could not write staged file.");cursor+=written;length-=written;}
}
static Digest Hash(HANDLE file) {
    struct State {
        BCRYPT_ALG_HANDLE algorithm=nullptr;BCRYPT_HASH_HANDLE hash=nullptr;
        std::vector<unsigned char> object;
        ~State(){if(hash)BCryptDestroyHash(hash);if(algorithm)BCryptCloseAlgorithmProvider(algorithm,0);}
    } state;
    if(BCryptOpenAlgorithmProvider(&state.algorithm,BCRYPT_SHA256_ALGORITHM,nullptr,0)<0)Fail("SHA-256 provider failed.");
    DWORD object_size=0,got=0;
    if(BCryptGetProperty(state.algorithm,BCRYPT_OBJECT_LENGTH,reinterpret_cast<PUCHAR>(&object_size),sizeof(object_size),&got,0)<0)Fail("SHA-256 initialization failed.");
    state.object.resize(object_size);
    if(BCryptCreateHash(state.algorithm,&state.hash,state.object.data(),object_size,nullptr,0,0)<0)Fail("SHA-256 initialization failed.");
    std::vector<unsigned char> buffer(1024*1024);
    Seek(file,0);
    for(;;){
        DWORD count=0;if(!ReadFile(file,buffer.data(),static_cast<DWORD>(buffer.size()),&count,nullptr))WinFail("Cannot hash file");
        if(!count)break;
        if(BCryptHashData(state.hash,buffer.data(),count,0)<0)Fail("SHA-256 update failed.");
    }
    Digest result={};if(BCryptFinishHash(state.hash,result.data(),static_cast<ULONG>(result.size()),0)<0)Fail("SHA-256 completion failed.");
    return result;
}
static Digest Hash(const fs::path& path){File file=ReadFileHandle(path);return Hash(file.h);}
static Digest Bytes(const unsigned char* bytes){Digest result;std::copy(bytes,bytes+32,result.begin());return result;}
static Digest ParseHash(const char* hex){
    Digest result={};
    auto digit=[](char ch)->unsigned {if(ch>='0'&&ch<='9')return ch-'0';if(ch>='a'&&ch<='f')return ch-'a'+10;if(ch>='A'&&ch<='F')return ch-'A'+10;Fail("Internal hash format error.");return 0;};
    for(unsigned i=0;i!=32;++i)result[i]=static_cast<unsigned char>((digit(hex[i*2])<<4)|digit(hex[i*2+1]));
    return result;
}
static void RequireHash(const fs::path& path,const Digest& expected,const char* message){if(Hash(path)!=expected)Fail(message);}
static fs::path PackageDirectory(){
    std::vector<wchar_t> text(32768);DWORD count=GetModuleFileNameW(nullptr,text.data(),static_cast<DWORD>(text.size()));
    if(!count||count>=text.size())WinFail("Cannot locate installer package");return fs::path(std::wstring(text.data(),count)).parent_path();
}
static PatchHeader ReadHeader(HANDLE patch){
#ifndef FXCOMPAT_TEST_BUILD
    if(Hash(patch)!=ParseHash(PAYLOAD_SHA256))Fail("The packaged v6 patch failed SHA-256 verification. No game files were changed.");
#endif
    PatchHeader header={};Seek(patch,0);ReadExact(patch,&header,sizeof(header));
    const char magic[8]={'F','X','P','A','T','C','H','1'};
    if(!std::equal(magic,magic+8,header.magic)||!header.original_size||!header.target_size||
        header.original_size>UINT32_MAX||header.target_size>UINT32_MAX||header.hunk_count>1000000)
        Fail("Unsupported or invalid patch header.");
    if(Bytes(header.original_hash)==Bytes(header.target_hash))Fail("Patch does not define a distinct modified executable.");
    return header;
}
static std::pair<Temp,File> NewTemp(const fs::path& directory,const wchar_t* kind){
    for(unsigned attempt=0;attempt!=100;++attempt){
        fs::path path=directory/(std::wstring(L".fxcompat-")+kind+L"-"+std::to_wstring(GetCurrentProcessId())+L"-"+std::to_wstring(GetTickCount64())+L"-"+std::to_wstring(attempt)+L".tmp");
        HANDLE file=CreateFileW(path.c_str(),GENERIC_READ|GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
        if(file!=INVALID_HANDLE_VALUE)return {Temp(path),File(file)};
        if(GetLastError()!=ERROR_FILE_EXISTS&&GetLastError()!=ERROR_ALREADY_EXISTS)WinFail("Cannot create staged file");
    }
    Fail("Cannot allocate a temporary filename.");return {Temp({}),File()};
}
static void CopyBytes(HANDLE source,HANDLE destination,uint64_t count){
    std::vector<unsigned char> buffer(1024*1024);Seek(source,0);Seek(destination,0);
    while(count){DWORD length=static_cast<DWORD>(std::min<uint64_t>(count,buffer.size()));ReadExact(source,buffer.data(),length);WriteExact(destination,buffer.data(),length);count-=length;}
}
static Temp StageCopy(HANDLE source,uint64_t size,const fs::path& directory,const wchar_t* kind,const Digest& expected){
    auto staged=NewTemp(directory,kind);CopyBytes(source,staged.second.h,size);
    if(!FlushFileBuffers(staged.second.h))WinFail("Cannot flush staged file");
    if(Hash(staged.second.h)!=expected)Fail("Staged copy failed SHA-256 verification.");
    staged.second.close();return std::move(staged.first);
}
static Temp StagePatched(HANDLE original,HANDLE patch,const PatchHeader& header,const fs::path& directory){
    auto staged=NewTemp(directory,L"patched");
    CopyBytes(original,staged.second.h,std::min(header.original_size,header.target_size));
    Seek(staged.second.h,header.target_size);if(!SetEndOfFile(staged.second.h))WinFail("Cannot size staged executable");
    Seek(patch,sizeof(PatchHeader));uint64_t previous_end=0;
    std::vector<unsigned char> buffer(1024*1024);
    for(uint32_t i=0;i<header.hunk_count;++i){
        HunkHeader hunk={};ReadExact(patch,&hunk,sizeof(hunk));
        if(!hunk.length||hunk.offset<previous_end||hunk.offset>header.target_size||hunk.length>header.target_size-hunk.offset)
            Fail("Patch hunks overlap or exceed the expected executable size.");
        previous_end=hunk.offset+hunk.length;Seek(staged.second.h,hunk.offset);uint32_t remaining=hunk.length;
        while(remaining){DWORD length=std::min<uint32_t>(remaining,static_cast<uint32_t>(buffer.size()));ReadExact(patch,buffer.data(),length);WriteExact(staged.second.h,buffer.data(),length);remaining-=length;}
    }
    unsigned char trailing=0;DWORD got=0;
    if(!ReadFile(patch,&trailing,1,&got,nullptr))WinFail("Cannot finish reading patch");
    if(got)Fail("Unexpected trailing data in patch file.");
    if(!FlushFileBuffers(staged.second.h))WinFail("Cannot flush staged executable");
    if(Size(staged.second.h)!=header.target_size||Hash(staged.second.h)!=Bytes(header.target_hash))
        Fail("Staged executable failed its final SHA-256 check. Nothing was installed.");
    staged.second.close();return std::move(staged.first);
}
static void Replace(Temp& source,const fs::path& destination){
    if(!MoveFileExW(source.path.c_str(),destination.c_str(),MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH))WinFail("Cannot replace file; close the game and try again");
    source.active=false;
}
static void EnsureBackup(const fs::path& game,const fs::path& backup,const Digest& original){
    if(Exists(backup)){RequireHash(backup,original,"Existing original backup has an unexpected hash; it will not be overwritten.");return;}
    if(!CopyFileW(game.c_str(),backup.c_str(),TRUE))WinFail("Cannot create original backup");
    RequireHash(backup,original,"The new original backup failed verification. The game was not replaced.");
}
#include "installer_portability.h"
static void RequireStopped(const fs::path& game){
    File snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0));
    if(snapshot.h==INVALID_HANDLE_VALUE)WinFail("Cannot check whether the game is running");
    PROCESSENTRY32W entry={};entry.dwSize=sizeof(entry);
    if(!Process32FirstW(snapshot.h,&entry))WinFail("Cannot inspect running processes");
    std::wstring expected=fs::absolute(game).wstring();
    do{
        if(_wcsicmp(entry.szExeFile,game.filename().c_str()))continue;
        File process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,entry.th32ProcessID));
        if(!process.h||process.h==INVALID_HANDLE_VALUE)Fail("A game process is running and cannot be inspected. Close the game first.");
        std::vector<wchar_t> text(32768);DWORD length=static_cast<DWORD>(text.size());
        if(!QueryFullProcessImageNameW(process.h,0,text.data(),&length))Fail("A game process is running and cannot be inspected. Close the game first.");
        std::wstring actual(text.data(),length);
        if(actual.rfind(L"\\\\?\\",0)==0)actual.erase(0,4);
        if(!_wcsicmp(actual.c_str(),expected.c_str()))Fail("The game is running. Close it before installing or restoring.");
    }while(Process32NextW(snapshot.h,&entry));
}
static void Install(const fs::path& directory,const fs::path& package,HANDLE patch,const PatchHeader& header){
    const fs::path game=directory/GAME_NAME,backup=directory/BACKUP_NAME,runtime=directory/RUNTIME_NAME;
    const Digest original_hash=Bytes(header.original_hash),target_hash=Bytes(header.target_hash),runtime_hash=ParseHash(RUNTIME_SHA256);
    const auto cpu=ReadCpuFacts();if(!MissingCpuFeatures(cpu).empty())Fail(MissingCpuMessage(cpu));
    RequireStopped(game);
    File current=ReadFileHandle(game);Digest current_hash=Hash(current.h);
    if(current_hash!=original_hash&&current_hash!=target_hash)Fail("This game executable does not match the supported original or patched build. No files were changed.");
    if(Exists(backup))RequireHash(backup,original_hash,"Existing original backup has an unexpected hash; it will not be overwritten.");
    bool runtime_existed=Exists(runtime);
    if(runtime_existed)RequireHash(runtime,runtime_hash,"An unrecognized fxcompat.dll already exists; it will not be overwritten.");
    File supplied_runtime=ReadFileHandle(package/RUNTIME_NAME);
    if(Hash(supplied_runtime.h)!=runtime_hash)Fail("The packaged runtime DLL failed verification.");
    if(current_hash==target_hash){
        if(!Exists(backup))Fail("The executable is patched but its original backup is missing. Installation was not changed.");
        if(!runtime_existed){Temp dll=StageCopy(supplied_runtime.h,Size(supplied_runtime.h),directory,L"runtime",runtime_hash);Replace(dll,runtime);}
        std::wcout<<L"Compatibility mod is already installed and verified.\n";return;
    }
    if(Size(current.h)!=header.original_size)Fail("Original executable size differs from the supported build.");
    Temp executable=StagePatched(current.h,patch,header,directory);
    Temp dll=StageCopy(supplied_runtime.h,Size(supplied_runtime.h),directory,L"runtime",runtime_hash);
    EnsureBackup(game,backup,original_hash);
    current.close(); // The verified backup exists before any installed file is replaced.
    bool added_runtime=false,game_replaced=false;
    try{
        if(!runtime_existed){Replace(dll,runtime);added_runtime=true;}
        Replace(executable,game);game_replaced=true;
        RequireHash(game,target_hash,"Installed executable verification failed.");
        RequireHash(runtime,runtime_hash,"Installed runtime verification failed.");
    }catch(...){
        bool original_available=!game_replaced;
        if(game_replaced){
            try{
                // Never overwrite an unrelated external change during recovery.
                Digest now=Hash(game);
                if(now==target_hash){File saved=ReadFileHandle(backup);Temp rollback=StageCopy(saved.h,header.original_size,directory,L"rollback",original_hash);Replace(rollback,game);RequireHash(game,original_hash,"Rollback verification failed.");original_available=true;}
                else if(now==original_hash)original_available=true;
            }catch(...){std::wcerr<<L"Automatic rollback could not finish. The verified original backup remains at:\n"<<backup.wstring()<<L"\n";}
        }
        if(added_runtime&&original_available){try{if(Exists(runtime)&&Hash(runtime)==runtime_hash)DeleteFileW(runtime.c_str());}catch(...){}}
        throw;
    }
    std::wcout<<L"Compatibility mod installed and verified.\nOriginal backup: "<<backup.wstring()<<L"\n";
}
static void Restore(const fs::path& directory,const PatchHeader& header){
    const fs::path game=directory/GAME_NAME,backup=directory/BACKUP_NAME,runtime=directory/RUNTIME_NAME;
    Digest original_hash=Bytes(header.original_hash),target_hash=Bytes(header.target_hash),runtime_hash=ParseHash(RUNTIME_SHA256);
    RequireStopped(game);
    File current=ReadFileHandle(game);Digest current_hash=Hash(current.h);
    if(current_hash==original_hash){std::wcout<<L"The original executable is already present. No files were changed.\n";return;}
    if(current_hash!=target_hash)Fail("Current executable is not this mod's patched build; it will not be overwritten.");
    File saved=ReadFileHandle(backup);
    if(Size(saved.h)!=header.original_size||Hash(saved.h)!=original_hash)Fail("Original backup failed verification; nothing was restored.");
    Temp restored=StageCopy(saved.h,header.original_size,directory,L"restore",original_hash);
    current.close();Replace(restored,game);RequireHash(game,original_hash,"Restored executable verification failed.");
    if(Exists(runtime)){
        if(Hash(runtime)==runtime_hash){if(!DeleteFileW(runtime.c_str()))std::wcout<<L"Original executable restored. Close any running game, then remove the unused fxcompat.dll if desired.\n";}
        else std::wcout<<L"An unrecognized fxcompat.dll was left unchanged.\n";
    }
    std::wcout<<L"Original executable restored and verified. The backup was retained.\n";
}
static void Verify(const fs::path& directory,const PatchHeader& header){
    const fs::path game=directory/GAME_NAME,backup=directory/BACKUP_NAME,runtime=directory/RUNTIME_NAME;
    Digest current_hash=Hash(game),original_hash=Bytes(header.original_hash),target_hash=Bytes(header.target_hash);
    if(current_hash==original_hash){
        std::wcout<<L"Original executable verified. The compatibility mod is not installed.\n";
        if(Exists(backup))RequireHash(backup,original_hash,"Existing backup is unrecognized.");
        return;
    }
    if(current_hash!=target_hash)Fail("Executable does not match the supported original or this mod's patched version.");
    RequireHash(backup,original_hash,"Original backup is unrecognized.");
    RequireHash(runtime,ParseHash(RUNTIME_SHA256),"Installed runtime DLL is unrecognized.");
    std::wcout<<L"Patched executable, runtime DLL, and original backup all verified.\n";
}
static std::string HexDigest(const Digest& digest){
    const char* digits="0123456789abcdef";std::string result;result.reserve(64);
    for(unsigned char byte:digest){result+=digits[byte>>4];result+=digits[byte&15];}return result;
}
static bool Diagnose(const fs::path& directory,const PatchHeader& header){
    bool okay=PrintCpuCheck(ReadCpuFacts());
    const Digest game=Hash(directory/GAME_NAME);
    const bool original=game==Bytes(header.original_hash),patched=game==Bytes(header.target_hash);
    std::cout<<"Game build: "<<(original?"supported original":patched?"supported v6 patched":"unrecognized")<<"\n";
    std::cout<<"Game SHA-256: "<<HexDigest(game)<<"\n";okay=okay&&(original||patched);
    const fs::path runtime=directory/RUNTIME_NAME;
    if(Exists(runtime)){
        const Digest digest=Hash(runtime);const bool recognized=digest==ParseHash(RUNTIME_SHA256);
        std::cout<<"Runtime: "<<(recognized?"recognized":"unrecognized")<<"\nRuntime SHA-256: "<<HexDigest(digest)<<"\n";
        if(patched&&!recognized)okay=false;
    }else{std::cout<<"Runtime: absent\n";if(patched)okay=false;}
    const fs::path backup=directory/BACKUP_NAME;
    if(Exists(backup)){
        const bool recognized=Hash(backup)==Bytes(header.original_hash);
        std::cout<<"Original backup: "<<(recognized?"verified":"unrecognized")<<"\n";if(!recognized)okay=false;
    }else{std::cout<<"Original backup: absent\n";if(patched)okay=false;}
    std::cout<<"Diagnostic check is read-only; no paths, account identifiers, or network data are included.\n";
    return okay;
}
static void Help(){
    std::wcout<<L"Final Fantasy VII Rebirth CPU compatibility installer 0.6.1\n\n"
        L"Usage: FxCompatInstaller.exe install|restore|verify [game-folder-or-exe]\n"
        L"       FxCompatInstaller.exe diagnose [game-folder-or-exe]\n"
        L"       FxCompatInstaller.exe list [--steam-root Steam-folder]\n"
        L"       FxCompatInstaller.exe --cpu-check\n"
        L"       FxCompatInstaller.exe --help\n\n"
        L"Close the game before installing or restoring. Saves are not touched.\n"
        L"Install verifies the original, builds and verifies the patched file locally,\n"
        L"and keeps a verified original backup. Unknown files are never overwritten.\n"
        L"Steam libraries are discovered automatically; multiple installations require\n"
        L"an explicit folder. You may drag the game folder onto a command file.\n"
        L"--steam-root can specify a Steam installation for discovery in any mode.\n"
        L"Verify, diagnose/check, list and cpu-check are read-only. No arguments show help.\n"
        L"Restore remains available even when the CPU prerequisite check fails.\n";
}
int wmain(int argc,wchar_t** argv){
    try{
#ifdef FXCOMPAT_TEST_BUILD
        std::cerr<<"FIXTURE TEST BUILD: NOT FOR DISTRIBUTION.\n";
#endif
        if(argc==1||(argc==2&&(std::wstring(argv[1])==L"--help"||std::wstring(argv[1])==L"-h"))){Help();return 0;}
        std::wstring mode=argv[1];if(mode.rfind(L"--",0)==0)mode.erase(0,2);
        if(mode==L"cpu-check"){if(argc!=2){Help();return 2;}return PrintCpuCheck(ReadCpuFacts())?0:1;}
        if(mode==L"check")mode=L"diagnose";
        if(mode!=L"install"&&mode!=L"restore"&&mode!=L"verify"&&mode!=L"diagnose"&&mode!=L"list"){Help();return 2;}
        fs::path explicitPath,steamRoot;
        for(int i=2;i<argc;++i){
            const std::wstring value=argv[i];
            if(value==L"--steam-root"){
                if(!steamRoot.empty()||i+1==argc)Fail("--steam-root requires one Steam folder.");steamRoot=argv[++i];
            }else if(value.rfind(L"--",0)==0||!explicitPath.empty())Fail("Unrecognized or duplicate argument. Use --help for usage.");
            else explicitPath=value;
        }
        if(mode==L"list"){
            if(!explicitPath.empty())Fail("Use --steam-root to select a Steam folder for discovery.");
            const auto games=DiscoverGames(steamRoot.empty()?SteamRoots():std::vector<fs::path>{steamRoot});
            if(games.empty()){std::wcout<<L"No Rebirth installations found. Supply the game folder explicitly.\n";return 1;}
            for(const auto& game:games)std::wcout<<game.wstring()<<L"\n";return 0;
        }
        const fs::path directory=ResolveGameDirectory(explicitPath,steamRoot,mode==L"diagnose");
        fs::path package=PackageDirectory();File patch=ReadFileHandle(package/PAYLOAD_NAME);PatchHeader header=ReadHeader(patch.h);
        if(mode==L"install")Install(directory,package,patch.h,header);
        else if(mode==L"restore")Restore(directory,header);
        else if(mode==L"verify")Verify(directory,header);
        else return Diagnose(directory,header)?0:1;
        return 0;
    }catch(const std::exception& error){std::cerr<<"Error: "<<error.what()<<"\n";return 1;}
}
