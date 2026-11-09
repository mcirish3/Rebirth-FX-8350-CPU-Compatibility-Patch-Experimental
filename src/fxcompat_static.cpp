#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <atomic>

// Static PE format shared with the patch builder. All addresses are RVAs.
struct FxSectionHeader {
    unsigned char magic[8];
    uint32_t version;
    uint32_t count;
    uint32_t entries_rva;
    uint32_t reserved0;
    uint32_t original_image_size;
    uint32_t reserved1;
};
struct FxEntry { uint32_t original_rva; uint32_t stub_rva; };
static_assert(sizeof(FxSectionHeader) == 32, "Header layout mismatch");
static_assert(sizeof(FxEntry) == 8, "Entry layout mismatch");

static constexpr unsigned TABLE_BITS = 17;
static constexpr unsigned TABLE_SIZE = 1u << TABLE_BITS;
static constexpr unsigned MAX_ENTRIES = TABLE_SIZE / 2;
static std::atomic<uintptr_t> g_keys[TABLE_SIZE] = {};
static std::atomic<uintptr_t> g_destinations[TABLE_SIZE] = {};
static PVOID g_handler = nullptr;
static unsigned g_count = 0;
static volatile LONG g_redirected = 0;
static HMODULE g_modules[256] = {};
static unsigned g_module_count = 0;
static HANDLE g_log = INVALID_HANDLE_VALUE;
static volatile LONG g_unmatched_logged = 0;

static void ReadInheritedLogHandle() {
    wchar_t text[64] = {};
    DWORD length = GetEnvironmentVariableW(L"FXCOMPAT_LOG_HANDLE", text, 64);
    if (!length || length >= 64) return;
    unsigned radix = 10, start = 0;
    if (length > 2 && text[0] == L'0' && (text[1] == L'x' || text[1] == L'X')) {
        radix = 16; start = 2;
    }
    uintptr_t value = 0;
    for (unsigned i = start; i != length; ++i) {
        unsigned digit;
        wchar_t ch = text[i];
        if (ch >= L'0' && ch <= L'9') digit = ch - L'0';
        else if (ch >= L'a' && ch <= L'f') digit = ch - L'a' + 10;
        else if (ch >= L'A' && ch <= L'F') digit = ch - L'A' + 10;
        else return;
        if (digit >= radix || value > (UINTPTR_MAX - digit) / radix) return;
        value = value * radix + digit;
    }
    if (value && value != UINTPTR_MAX) g_log = reinterpret_cast<HANDLE>(value);
}

struct JsonLine {
    char bytes[4096];
    DWORD size;
    void add(const char* text) { while (*text && size < sizeof(bytes)) bytes[size++] = *text++; }
    void hex(uint64_t value, unsigned digits = 16, bool prefix = true) {
        static const char symbols[] = "0123456789abcdef";
        if (prefix) add("0x");
        for (unsigned i = digits; i && size < sizeof(bytes); --i)
            bytes[size++] = symbols[(value >> ((i - 1) * 4)) & 15];
    }
    void field(const char* name, uint64_t value) {
        add(",\""); add(name); add("\":\""); hex(value); add("\"");
    }
};

// Without an inherited log handle, unmatched instructions go to
// "fxreborn-missed.log" next to the game. The patcher reads this file and adds
// the addresses on its next run, so a site the static scan missed after a game
// update only has to be found once.
static HANDLE OpenMissedLog() {
    wchar_t path[MAX_PATH + 32] = {};
    DWORD n = GetModuleFileNameW(nullptr, path, MAX_PATH);
    if (!n || n >= MAX_PATH) return INVALID_HANDLE_VALUE;
    while (n && path[n - 1] != L'\\') --n;
    const wchar_t name[] = L"fxreborn-missed.log";
    for (unsigned i = 0; i != sizeof(name) / sizeof(name[0]); ++i) path[n + i] = name[i];
    return CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                       OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
}

static void LogUnmatched(EXCEPTION_POINTERS* ep) {
    if (InterlockedCompareExchange(&g_unmatched_logged, 1, 0)) return;
    DWORD saved_error = GetLastError();
    if (g_log == INVALID_HANDLE_VALUE) g_log = OpenMissedLog();
    if (g_log == INVALID_HANDLE_VALUE) { SetLastError(saved_error); return; }
    const CONTEXT* context = ep->ContextRecord;
    JsonLine line = {};
    line.add("{\"event\":\"unmatched_illegal_instruction\"");
    line.field("code", ep->ExceptionRecord->ExceptionCode);
    line.field("process_id", GetCurrentProcessId());
    line.field("thread_id", GetCurrentThreadId());
    line.field("rip", context->Rip);
    MEMORY_BASIC_INFORMATION region = {};
    if (VirtualQuery(reinterpret_cast<void*>(context->Rip), &region, sizeof(region))) {
        line.field("allocation_base", reinterpret_cast<uintptr_t>(region.AllocationBase));
        line.field("rva", context->Rip - reinterpret_cast<uintptr_t>(region.AllocationBase));
        line.field("memory_type", region.Type);
        line.field("main_module", region.AllocationBase == GetModuleHandleW(nullptr));
    }
    line.add(",\"bytes\":\"");
    __try {
        auto* source = reinterpret_cast<const unsigned char*>(context->Rip);
        for (unsigned i=0; i!=32; ++i) line.hex(source[i],2,false);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // A partial byte sequence remains valid JSON and avoids another fault.
    }
    line.add("\"");
    line.field("rax",context->Rax); line.field("rcx",context->Rcx); line.field("rdx",context->Rdx);
    line.field("rbx",context->Rbx); line.field("rsp",context->Rsp); line.field("rbp",context->Rbp);
    line.field("rsi",context->Rsi); line.field("rdi",context->Rdi);
    line.field("r8",context->R8); line.field("r9",context->R9); line.field("r10",context->R10);
    line.field("r11",context->R11); line.field("r12",context->R12); line.field("r13",context->R13);
    line.field("r14",context->R14); line.field("r15",context->R15);
    line.field("rflags",context->EFlags); line.field("mxcsr",context->MxCsr);
    line.add("}\n");
    DWORD written = 0;
    WriteFile(g_log,line.bytes,line.size,&written,nullptr);
    SetLastError(saved_error);
}

static unsigned Hash(uintptr_t value) {
    return static_cast<unsigned>(((value >> 2) * UINT64_C(0x9e3779b97f4a7c15)) >> (64 - TABLE_BITS));
}

static bool Add(uintptr_t original, uintptr_t destination) {
    if (!original || !destination || original == destination) return false;
    unsigned index = Hash(original);
    for (unsigned probes = 0; probes != TABLE_SIZE; ++probes, index = (index + 1) & (TABLE_SIZE - 1)) {
        uintptr_t key = g_keys[index].load(std::memory_order_relaxed);
        if (key == original) return g_destinations[index].load(std::memory_order_relaxed) == destination;
        if (!key) {
            if (g_count >= MAX_ENTRIES) return false;
            g_destinations[index].store(destination, std::memory_order_relaxed);
            g_keys[index].store(original, std::memory_order_release);
            ++g_count;
            return true;
        }
    }
    return false;
}

static LONG WINAPI Redirect(EXCEPTION_POINTERS* ep) {
    if (!ep || !ep->ExceptionRecord || !ep->ContextRecord ||
        ep->ExceptionRecord->ExceptionCode != EXCEPTION_ILLEGAL_INSTRUCTION)
        return EXCEPTION_CONTINUE_SEARCH;
    uintptr_t source = static_cast<uintptr_t>(ep->ContextRecord->Rip);
    unsigned index = Hash(source);
    for (unsigned probes = 0; probes != TABLE_SIZE; ++probes, index = (index + 1) & (TABLE_SIZE - 1)) {
        uintptr_t key = g_keys[index].load(std::memory_order_acquire);
        if (!key) break;
        if (key == source) {
            ep->ContextRecord->Rip = g_destinations[index].load(std::memory_order_acquire);
            InterlockedIncrement(&g_redirected);
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    LogUnmatched(ep);
    return EXCEPTION_CONTINUE_SEARCH;
}

static bool Fits(uint32_t start, uint64_t length, uint32_t lower, uint32_t upper) {
    return start >= lower && uint64_t(start) + length <= upper;
}

static bool InitializeImage(HMODULE main_module) {
    for (unsigned i=0; i!=g_module_count; ++i) if (g_modules[i]==main_module) return true;
    if (!main_module || g_module_count==256) return false;
    auto* base = reinterpret_cast<unsigned char*>(main_module);
    __try {
        auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < sizeof(IMAGE_DOS_HEADER) || dos->e_lfanew > 0x100000)
            return false;
        auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE || nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
            nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC || nt->FileHeader.NumberOfSections > 96)
            return false;
        uint32_t image_size = nt->OptionalHeader.SizeOfImage;
        auto* sections = IMAGE_FIRST_SECTION(nt);
        const IMAGE_SECTION_HEADER* target = nullptr;
        for (unsigned i = 0; i != nt->FileHeader.NumberOfSections; ++i) {
            const unsigned char* n = sections[i].Name;
            if (n[0]=='.' && n[1]=='f' && n[2]=='x' && n[3]=='c' && n[4]=='p' && n[5]=='t' && n[6]==0 && n[7]==0) {
                if (target) return false;
                target = sections + i;
            }
        }
        // This allows the DLL to be loaded by an unpatched validation host.
        if (!target) return true;
        uint32_t begin = target->VirtualAddress;
        uint64_t end64 = uint64_t(begin) + target->Misc.VirtualSize;
        if (end64 > image_size || target->Misc.VirtualSize < sizeof(FxSectionHeader) ||
            !(target->Characteristics & IMAGE_SCN_MEM_EXECUTE) || !(target->Characteristics & IMAGE_SCN_MEM_READ))
            return false;
        uint32_t end = static_cast<uint32_t>(end64);
        auto* header = reinterpret_cast<const FxSectionHeader*>(base + begin);
        static const unsigned char magic[] = {'F','X','C','P','T','0','0','1'};
        for (unsigned i=0; i!=8; ++i) if (header->magic[i] != magic[i]) return false;
        if (header->version != 1 || header->count > MAX_ENTRIES || header->reserved0 || header->reserved1 ||
            !header->original_image_size || header->original_image_size > begin ||
            !Fits(header->entries_rva, uint64_t(header->count)*sizeof(FxEntry), begin+sizeof(FxSectionHeader), end))
            return false;
        auto* entries = reinterpret_cast<const FxEntry*>(base + header->entries_rva);
        for (unsigned i = 0; i != header->count; ++i) {
            const FxEntry& entry = entries[i];
            if (entry.original_rva >= header->original_image_size || !Fits(entry.stub_rva, 1, begin, end))
                return false;
            // Original sites must belong to an original executable section.
            bool executable_source = false;
            for (unsigned j=0; j!=nt->FileHeader.NumberOfSections; ++j) {
                const IMAGE_SECTION_HEADER& section = sections[j];
                if (&section != target && (section.Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
                    uint64_t(entry.original_rva) >= section.VirtualAddress &&
                    uint64_t(entry.original_rva) < uint64_t(section.VirtualAddress)+section.Misc.VirtualSize) {
                    executable_source = true;
                    break;
                }
            }
            if (!executable_source || !Add(reinterpret_cast<uintptr_t>(base)+entry.original_rva,
                                           reinterpret_cast<uintptr_t>(base)+entry.stub_rva))
                return false;
        }
        // Always installed for a patched image, so missed sites are logged.
        if (!g_handler) {
            g_handler = AddVectoredExceptionHandler(1, Redirect);
            if (!g_handler) return false;
        }
        g_modules[g_module_count++] = main_module;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

extern "C" __declspec(dllexport) void WINAPI FxCompatImportAnchor() {}
// Intended for an auxiliary module's process-attach wrapper, under the loader
// lock. Registration must not race other registrations. The handler hot path
// remains lock-free while immutable keys are published.
extern "C" __declspec(dllexport) DWORD WINAPI FxCompatRegisterModule(HMODULE module) {
    return InitializeImage(module) ? ERROR_SUCCESS : ERROR_BAD_EXE_FORMAT;
}
extern "C" __declspec(dllexport) DWORD WINAPI FxCompatGetRegisteredCount() { return g_count; }
extern "C" __declspec(dllexport) DWORD WINAPI FxCompatGetRedirectedCount() {
    return static_cast<DWORD>(InterlockedCompareExchange(&g_redirected,0,0));
}

BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        ReadInheritedLogHandle();
        if (!InitializeImage(GetModuleHandleW(nullptr))) {
            SetLastError(ERROR_BAD_EXE_FORMAT);
            return FALSE;
        }
    } else if (reason == DLL_PROCESS_DETACH && !reserved && g_handler) {
        RemoveVectoredExceptionHandler(g_handler);
        g_handler = nullptr;
    }
    return TRUE;
}
