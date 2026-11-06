#pragma once
#include <cctype>
#include <set>

// Included after the installer's file primitives. Only Steam's library list and
// appmanifest_2909400.acf are inspected; no other account/app configuration is read.
struct VdfNode {std::string key,value;std::vector<VdfNode> children;bool object=false;};
class VdfParser {
    const std::string& text;size_t at=0,nodes=0;
    void skip(){
        for(;;){while(at<text.size()&&std::isspace(static_cast<unsigned char>(text[at])))++at;
            if(at+1<text.size()&&text[at]=='/'&&text[at+1]=='/'){while(at<text.size()&&text[at]!='\n')++at;}else break;}
    }
    std::string token(){
        skip();if(at>=text.size())Fail("Incomplete Steam configuration file.");
        if(text[at]=='{'||text[at]=='}')return std::string(1,text[at++]);
        std::string result;
        if(text[at]=='"'){
            ++at;
            while(at<text.size()){
                char ch=text[at++];if(ch=='"')return result;
                if(ch=='\\'&&at<text.size()&&(text[at]=='\\'||text[at]=='"'))ch=text[at++];
                result.push_back(ch);
            }
            Fail("Unterminated string in Steam configuration.");
        }
        while(at<text.size()&&!std::isspace(static_cast<unsigned char>(text[at]))&&text[at]!='{'&&text[at]!='}')result.push_back(text[at++]);
        if(result.empty())Fail("Invalid Steam configuration token.");return result;
    }
    std::vector<VdfNode> parse(unsigned depth,bool nested){
        if(depth>16)Fail("Steam configuration nesting is too deep.");
        std::vector<VdfNode> result;
        for(;;){
            skip();if(at==text.size()){if(nested)Fail("Incomplete Steam configuration object.");return result;}
            if(text[at]=='}'){if(!nested)Fail("Unexpected Steam configuration terminator.");++at;return result;}
            VdfNode node;node.key=token();if(node.key=="{"||node.key=="}")Fail("Invalid Steam configuration key.");
            std::string value=token();
            if(value=="{"){node.object=true;node.children=parse(depth+1,true);}
            else if(value=="}")Fail("Missing Steam configuration value.");else node.value=std::move(value);
            if(++nodes>20000)Fail("Steam configuration has too many entries.");result.push_back(std::move(node));
        }
    }
public:
    explicit VdfParser(const std::string& input):text(input){if(text.size()>=3&&text.compare(0,3,"\xef\xbb\xbf")==0)at=3;}
    std::vector<VdfNode> read(){return parse(0,false);}
};
static const VdfNode* VdfFind(const std::vector<VdfNode>& nodes,const char* key){
    for(const auto& node:nodes)if(_stricmp(node.key.c_str(),key)==0)return &node;return nullptr;
}
static std::wstring Utf8Wide(const std::string& value){
    if(value.empty())return {};
    const int size=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,value.data(),static_cast<int>(value.size()),nullptr,0);
    if(!size)Fail("A Steam path is not valid UTF-8. Supply the game folder directly.");
    std::wstring result(static_cast<size_t>(size),L'\0');
    MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,value.data(),static_cast<int>(value.size()),result.data(),size);return result;
}
static std::vector<VdfNode> ReadVdf(const fs::path& path){
    File file=ReadFileHandle(path);const auto size=Size(file.h);if(size>2*1024*1024)Fail("Steam configuration file is unexpectedly large.");
    std::string data(static_cast<size_t>(size),'\0');if(size)ReadExact(file.h,data.data(),static_cast<DWORD>(size));
    return VdfParser(data).read();
}
static bool RegularFile(const fs::path& path){std::error_code ec;return fs::is_regular_file(path,ec);}
static void AddUniquePath(std::vector<fs::path>& paths,const fs::path& value){
    if(value.empty())return;std::error_code ec;fs::path normalized=fs::weakly_canonical(fs::absolute(value),ec);
    if(ec)normalized=fs::absolute(value).lexically_normal();
    for(const auto& existing:paths)if(!_wcsicmp(existing.c_str(),normalized.c_str()))return;
    paths.push_back(normalized);
}
static std::wstring RegistryString(HKEY hive,const wchar_t* key,const wchar_t* value,REGSAM view=0){
    HKEY handle=nullptr;if(RegOpenKeyExW(hive,key,0,KEY_QUERY_VALUE|view,&handle)!=ERROR_SUCCESS)return {};
    DWORD type=0,bytes=0;std::wstring result;
    if(RegQueryValueExW(handle,value,nullptr,&type,nullptr,&bytes)==ERROR_SUCCESS&&type==REG_SZ&&bytes<=65536&&bytes>=sizeof(wchar_t)){
        std::vector<wchar_t> data(bytes/sizeof(wchar_t)+1,L'\0');
        if(RegQueryValueExW(handle,value,nullptr,&type,reinterpret_cast<BYTE*>(data.data()),&bytes)==ERROR_SUCCESS)result=data.data();
    }
    RegCloseKey(handle);return result;
}
static std::vector<fs::path> SteamRoots(){
    std::vector<fs::path> result;
    AddUniquePath(result,RegistryString(HKEY_CURRENT_USER,L"Software\\Valve\\Steam",L"SteamPath"));
    AddUniquePath(result,RegistryString(HKEY_LOCAL_MACHINE,L"Software\\Valve\\Steam",L"InstallPath",KEY_WOW64_32KEY));
    AddUniquePath(result,RegistryString(HKEY_LOCAL_MACHINE,L"Software\\Valve\\Steam",L"InstallPath",KEY_WOW64_64KEY));
    wchar_t programFiles[32768]={};const DWORD length=GetEnvironmentVariableW(L"ProgramFiles(x86)",programFiles,32768);
    if(length&&length<32768)AddUniquePath(result,fs::path(programFiles)/L"Steam");
    return result;
}
static bool IsChildPath(const fs::path& parent,const fs::path& child){
    auto a=parent.begin(),b=child.begin();for(;a!=parent.end();++a,++b)if(b==child.end()||_wcsicmp(a->c_str(),b->c_str()))return false;
    return b!=child.end();
}
static std::vector<fs::path> DiscoverGames(const std::vector<fs::path>& roots){
    std::vector<fs::path> libraries,games;
    for(const auto& root:roots){
        AddUniquePath(libraries,root);const fs::path config=root/L"steamapps"/L"libraryfolders.vdf";
        if(!RegularFile(config))continue;
        auto document=ReadVdf(config);const VdfNode* list=VdfFind(document,"libraryfolders");
        if(!list||!list->object)Fail("Steam's library list has an unsupported format. Supply the game folder directly.");
        for(const auto& node:list->children){
            if(node.key.empty()||!std::all_of(node.key.begin(),node.key.end(),[](unsigned char ch){return ch>='0'&&ch<='9';}))continue;
            const VdfNode* path=node.object?VdfFind(node.children,"path"):nullptr;
            std::string value=node.object?(path?path->value:std::string()):node.value;
            if(!value.empty()){
                fs::path candidate=Utf8Wide(value);if(!candidate.is_absolute())Fail("Steam contains a relative library path. Supply the game folder directly.");
                AddUniquePath(libraries,candidate);
            }
        }
    }
    for(const auto& library:libraries){
        const fs::path manifest=library/L"steamapps"/L"appmanifest_2909400.acf";
        if(!RegularFile(manifest))continue;
        auto document=ReadVdf(manifest);const VdfNode* app=VdfFind(document,"AppState");
        const VdfNode* id=app&&app->object?VdfFind(app->children,"appid"):nullptr;
        const VdfNode* folder=app&&app->object?VdfFind(app->children,"installdir"):nullptr;
        if(!id||id->value!="2909400"||!folder||folder->value.empty())Fail("Rebirth's Steam manifest is incomplete. Supply the game folder directly.");
        const fs::path relative=Utf8Wide(folder->value);
        if(relative.is_absolute()||relative.has_root_path())Fail("Steam's game folder must be relative to its library.");
        for(const auto& part:relative)if(part==L".."||part==L".")Fail("Steam's game folder contains an unsafe path component.");
        std::error_code ec;const fs::path common=fs::weakly_canonical(library/L"steamapps"/L"common",ec);
        if(ec)continue;const fs::path candidate=fs::weakly_canonical(common/relative/L"End"/L"Binaries"/L"Win64",ec);
        if(ec||!IsChildPath(common,candidate))Fail("Steam's game folder resolves outside its library. Supply the intended game folder directly.");
        if(RegularFile(candidate/GAME_NAME))AddUniquePath(games,candidate);
    }
    return games;
}
static fs::path ExplicitGameDirectory(fs::path path){
    path=fs::absolute(path).lexically_normal();
    if(RegularFile(path)){
        if(_wcsicmp(path.filename().c_str(),GAME_NAME)&&_wcsicmp(path.filename().c_str(),L"ff7rebirth.exe"))Fail("Choose the Rebirth game folder or one of its game executables.");
        path=path.parent_path();
    }
    if(RegularFile(path/GAME_NAME))return path;
    const fs::path nested=path/L"End"/L"Binaries"/L"Win64";
    if(RegularFile(nested/GAME_NAME))return nested;
    Fail("The selected folder does not contain Rebirth's game executable. Choose the game root or End\\Binaries\\Win64.");return {};
}
static fs::path ResolveGameDirectory(const fs::path& explicitPath,const fs::path& steamRoot,bool privateOutput=false){
    if(!explicitPath.empty())return ExplicitGameDirectory(explicitPath);
    const auto games=DiscoverGames(steamRoot.empty()?SteamRoots():std::vector<fs::path>{steamRoot});
    if(games.size()==1)return games.front();
    if(!privateOutput&&games.size()>1){std::wcout<<L"More than one Rebirth installation was found:\n";for(const auto& game:games)std::wcout<<L"  "<<game.wstring()<<L"\n";}
    if(games.empty())Fail("No Rebirth installation was found. Drag the game folder onto the Install/Restore/Verify command file, or supply its folder as an argument.");
    Fail("More than one Rebirth installation was found. Choose explicitly by dragging the intended game folder onto the command file or supplying its folder as an argument.");return {};
}
