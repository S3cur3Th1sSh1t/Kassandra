/*
 * kassandra - ETW-based threat detection tool
 *
 * Reimplementation of tracer_v2 (tracebit.cli).
 * Monitors Windows processes via kernel+user ETW tracing and flags suspicious
 * behaviors: public/private/tunneled network connections, dynamic code
 * execution, DLL ballooning (security-DLL bitmask), thread-pool callback
 * abuse (FNV-1a export resolution), and service-port accumulation.
 *
 * Build (MSVC):
 *   cl /O2 kassandra.c /link advapi32.lib tdh.lib ws2_32.lib ntdll.lib ole32.lib
 *
 * Requires elevation (SeSystemProfilePrivilege).
 */

#define _CRT_SECURE_NO_WARNINGS
#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "ole32.lib")

/* ── Tag bitmask (per-process detection flags) ─────────────────────── */
#define TAG_NET_PUBLIC            0x0001
#define TAG_NET_PRIVATE           0x0002
#define TAG_NET_TUNNEL            0x0004
#define TAG_DYNAMIC_CODE          0x0008
#define TAG_DYNAMIC_CODE_NESTED   0x0010
#define TAG_SLEEP_TP_CALLBACK     0x0020
#define TAG_PROXY_TP_CALLBACK     0x0040
#define TAG_MODULE_BALLOON        0x0080
#define TAG_HIGH_SERVICE_PORTS    0x0100

/* ── Severity levels ───────────────────────────────────────────────── */
#define LEVEL_NONE     0
#define LEVEL_INFO     1
#define LEVEL_LOW      2
#define LEVEL_MEDIUM   3
#define LEVEL_HIGH     4
/* ── Console colors (Windows console attributes) ───────────────────── */
#define COLOR_DEFAULT  0x07
#define COLOR_INFO     0x08  /* dark gray */
#define COLOR_LOW      0x0A  /* green     */
#define COLOR_MEDIUM   0x0E  /* yellow    */
#define COLOR_HIGH     0x0C  /* red       */
#define COLOR_BANNER   0x0B  /* cyan      */

/* ── FNV-1a 64-bit constants ───────────────────────────────────────── */
#define FNV_OFFSET_BASIS 0xcbf29ce484222325ULL
#define FNV_PRIME        0x100000001b3ULL

/* ── Common Windows service ports ──────────────────────────────────── */
static const USHORT SERVICE_PORTS[] = {
    88, 135, 139, 389, 445, 636, 3268, 3269, 3389, 5985, 5986,
};
#define NUM_SERVICE_PORTS (sizeof(SERVICE_PORTS) / sizeof(SERVICE_PORTS[0]))
#define SERVICE_PORT_THRESHOLD 5

/* ── 28 security-related DLLs for balloon detection (case-insensitive) */
static const WCHAR *BALLOON_DLLS[] = {
    L"samcli.dll",    L"dsrole.dll",    L"logoncli.dll",  L"activeds.dll",
    L"adsldpc.dll",   L"wldap32.dll",   L"srvcli.dll",    L"dbghelp.dll",
    L"dbgcore.dll",   L"vaultcli.dll",  L"samlib.dll",    L"dpapi.dll",
    L"cryptdll.dll",  L"taskschd.dll",  L"wtsapi32.dll",  L"winsta.dll",
    L"wbemcomn.dll",  L"wbemsvc.dll",   L"fastprox.dll",  L"kerberos.dll",
    L"msv1_0.dll",    L"tspkg.dll",     L"wdigest.dll",   L"cloudap.dll",
    L"gpapi.dll",     L"authz.dll",     L"ntdsapi.dll",   L"dsparse.dll",
};
#define NUM_BALLOON_DLLS 28
#define BALLOON_THRESHOLD 6

/* ── Sleep API names (for FNV-1a hash matching) ────────────────────── */
static const char *SLEEP_API_NAMES[] = {
    "NtDelayExecution", "SleepEx", "Sleep",
    "WaitForSingleObject", "WaitForSingleObjectEx",
    "WaitForMultipleObjects", "WaitForMultipleObjectsEx",
    "NtWaitForSingleObject", "NtWaitForMultipleObjects",
    "SleepConditionVariableSRW", "SleepConditionVariableCS",
    NULL
};

/* ── Proxy API names (for FNV-1a hash matching) ────────────────────── */
static const char *PROXY_API_NAMES[] = {
    "RtlAllocateHeap", "RtlCreateHeap", "RtlMoveMemory", "RtlCopyMemory",
    "RtlCreateUserThread", "RtlQueueApcWow64Thread", "RtlDispatchAPC",
    "ResumeThread", "RtlAddVectoredExceptionHandler",
    "RtlRemoveVectoredExceptionHandler",
    "NtContinue", "ZwContinue", "RtlCaptureContext",
    "NtTestAlert", "ZwTestAlert",
    "NtSuspendThread", "ZwSuspendThread", "NtResumeThread", "ZwResumeThread",
    "NtAlertResumeThread", "ZwAlertResumeThread",
    "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
    "LoadPackagedLibrary", "LdrLoadDll",
    "LdrGetProcedureAddress", "LdrGetProcedureAddressEx",
    "LdrGetProcedureAddressForCaller",
    "NtReadVirtualMemory", "ZwReadVirtualMemory",
    "NtWriteVirtualMemory", "ZwWriteVirtualMemory",
    NULL
};

/* ── FNV-1a hash computation ───────────────────────────────────────── */
static ULONGLONG fnv1a_hash(const char *str) {
    ULONGLONG h = FNV_OFFSET_BASIS;
    while (*str) {
        h ^= (unsigned char)*str++;
        h *= FNV_PRIME;
    }
    return h;
}

/* ── FNV-1a hash set (open-addressing, power-of-2 size) ────────────── */
#define HASH_SET_SIZE 256

typedef struct {
    ULONGLONG buckets[HASH_SET_SIZE];
    int       count;
} hash_set_t;

static void hash_set_init(hash_set_t *set) {
    memset(set, 0, sizeof(*set));
}

static void hash_set_insert(hash_set_t *set, ULONGLONG h) {
    ULONG idx = (ULONG)(h & (HASH_SET_SIZE - 1));
    while (set->buckets[idx] != 0) {
        if (set->buckets[idx] == h) return;
        idx = (idx + 1) & (HASH_SET_SIZE - 1);
    }
    set->buckets[idx] = h;
    set->count++;
}

static int hash_set_contains(const hash_set_t *set, ULONGLONG h) {
    if (h == 0) return 0;
    ULONG idx = (ULONG)(h & (HASH_SET_SIZE - 1));
    while (set->buckets[idx] != 0) {
        if (set->buckets[idx] == h) return 1;
        idx = (idx + 1) & (HASH_SET_SIZE - 1);
    }
    return 0;
}

static hash_set_t g_sleep_hashes;
static hash_set_t g_proxy_hashes;

static void init_api_hash_sets(void) {
    hash_set_init(&g_sleep_hashes);
    hash_set_init(&g_proxy_hashes);
    for (int i = 0; SLEEP_API_NAMES[i]; i++)
        hash_set_insert(&g_sleep_hashes, fnv1a_hash(SLEEP_API_NAMES[i]));
    for (int i = 0; PROXY_API_NAMES[i]; i++)
        hash_set_insert(&g_proxy_hashes, fnv1a_hash(PROXY_API_NAMES[i]));
}

/* ── Export entry (resolved from PE export table) ──────────────────── */
typedef struct {
    ULONG64 func_start;
    ULONG64 func_end;
    char    name[64];
} export_entry_t;

/* Per-module resolved exports (sorted by func_start) */
typedef struct {
    export_entry_t *entries;
    int count;
    int capacity;
    ULONG64 base;
    ULONG64 size;
} module_exports_t;

/* Three system modules we resolve exports from */
static module_exports_t g_ntdll_exports;
static module_exports_t g_kernel32_exports;
static module_exports_t g_kernelbase_exports;

static int export_cmp(const void *a, const void *b) {
    const export_entry_t *ea = (const export_entry_t *)a;
    const export_entry_t *eb = (const export_entry_t *)b;
    if (ea->func_start < eb->func_start) return -1;
    if (ea->func_start > eb->func_start) return 1;
    return 0;
}

static void resolve_module_exports(module_exports_t *mod, const char *dll_name) {
    HMODULE hMod = GetModuleHandleA(dll_name);
    if (!hMod) return;

    mod->base = (ULONG64)hMod;

    BYTE *base = (BYTE *)hMod;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;

    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;

    /* Find .text section for size */
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    ULONG64 text_start = 0, text_end = 0;
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(sec[i].Name, ".text", 5) == 0) {
            text_start = mod->base + sec[i].VirtualAddress;
            text_end = text_start + sec[i].Misc.VirtualSize;
            break;
        }
    }
    mod->size = nt->OptionalHeader.SizeOfImage;

    IMAGE_DATA_DIRECTORY *expDir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (expDir->VirtualAddress == 0 || expDir->Size == 0) return;

    IMAGE_EXPORT_DIRECTORY *exp =
        (IMAGE_EXPORT_DIRECTORY *)(base + expDir->VirtualAddress);

    DWORD *names     = (DWORD *)(base + exp->AddressOfNames);
    WORD  *ordinals  = (WORD  *)(base + exp->AddressOfNameOrdinals);
    DWORD *functions = (DWORD *)(base + exp->AddressOfFunctions);

    int n = exp->NumberOfNames;
    mod->capacity = n;
    mod->entries = (export_entry_t *)calloc(n, sizeof(export_entry_t));
    if (!mod->entries) return;
    mod->count = 0;

    for (int i = 0; i < n; i++) {
        char *name = (char *)(base + names[i]);
        DWORD rva = functions[ordinals[i]];
        ULONG64 va = mod->base + rva;

        /* Skip forwarder entries (pointing into the export directory itself) */
        if (rva >= expDir->VirtualAddress &&
            rva < expDir->VirtualAddress + expDir->Size)
            continue;

        export_entry_t *e = &mod->entries[mod->count];
        strncpy(e->name, name, sizeof(e->name) - 1);
        e->func_start = va;

        /* Estimate function end:
         * Nt/Zw syscall stubs are 0x20 bytes.
         * Other functions: scan for 0xCC padding or use next export. */
        if ((name[0] == 'N' && name[1] == 't') ||
            (name[0] == 'Z' && name[1] == 'w')) {
            e->func_end = va + 0x20;
        } else {
            e->func_end = va + 0x500; /* placeholder, refined after sort */
        }

        mod->count++;
    }

    /* Sort by address */
    qsort(mod->entries, mod->count, sizeof(export_entry_t), export_cmp);

    /* Refine func_end: use next function's start, or text_end */
    for (int i = 0; i < mod->count; i++) {
        export_entry_t *e = &mod->entries[i];
        /* Don't refine Nt/Zw stubs (already have exact size) */
        if ((e->name[0] == 'N' && e->name[1] == 't') ||
            (e->name[0] == 'Z' && e->name[1] == 'w'))
            continue;

        if (i + 1 < mod->count) {
            e->func_end = mod->entries[i + 1].func_start;
        } else if (text_end) {
            e->func_end = text_end;
        }
    }
}

/* Binary search: find which export contains a given address */
static const char *resolve_address_to_export(const module_exports_t *mod,
                                             ULONG64 addr) {
    if (!mod->entries || mod->count == 0) return NULL;
    if (addr < mod->base || addr >= mod->base + mod->size) return NULL;

    int lo = 0, hi = mod->count - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        if (addr < mod->entries[mid].func_start) {
            hi = mid - 1;
        } else if (addr >= mod->entries[mid].func_end) {
            lo = mid + 1;
        } else {
            return mod->entries[mid].name;
        }
    }
    return NULL;
}

static const char *resolve_address_in_system_dlls(ULONG64 addr) {
    const char *name;
    name = resolve_address_to_export(&g_ntdll_exports, addr);
    if (name) return name;
    name = resolve_address_to_export(&g_kernel32_exports, addr);
    if (name) return name;
    name = resolve_address_to_export(&g_kernelbase_exports, addr);
    if (name) return name;
    return NULL;
}

static int is_address_in_system_dlls(ULONG64 addr) {
    if (g_ntdll_exports.base && addr >= g_ntdll_exports.base &&
        addr < g_ntdll_exports.base + g_ntdll_exports.size)
        return 1;
    if (g_kernel32_exports.base && addr >= g_kernel32_exports.base &&
        addr < g_kernel32_exports.base + g_kernel32_exports.size)
        return 1;
    if (g_kernelbase_exports.base && addr >= g_kernelbase_exports.base &&
        addr < g_kernelbase_exports.base + g_kernelbase_exports.size)
        return 1;
    return 0;
}

/* ── Module record (loaded DLLs per process) ───────────────────────── */
typedef struct module_entry {
    ULONG64 base;
    ULONG64 size;
    struct module_entry *next;
} module_entry_t;

/* ── Dynamic allocation record (pages touched by dynamic code) ──────── */
typedef struct dynalloc_entry {
    ULONG64 page_base;
    struct dynalloc_entry *next;
} dynalloc_entry_t;

/* ── Service port tracking (unique ports per process) ──────────────── */
typedef struct port_entry {
    USHORT port;
    struct port_entry *next;
} port_entry_t;

/* ── Process record ────────────────────────────────────────────────── */
typedef struct process_record {
    ULONG pid;
    WCHAR image[260];
    USHORT tags;
    int emitted_level;    /* highest level already emitted for this process */
    module_entry_t *modules;
    int module_count;
    port_entry_t *service_ports;
    int service_port_count;
    ULONG balloon_mask;   /* bitmask of loaded security DLLs (28 bits) */
    dynalloc_entry_t *dynallocs;  /* pages allocated/touched by dynamic code */
    struct process_record *next;
} process_record_t;

/* ── Global state ──────────────────────────────────────────────────── */
#define PROC_HASH_SIZE 1024

static process_record_t *g_proc_table[PROC_HASH_SIZE];
static CRITICAL_SECTION  g_proc_lock;
static CRITICAL_SECTION  g_output_lock;
static volatile LONG     g_running = 1;
static volatile LONG     g_rundown_active = 0; /* suppress detections during rundown */
static int               g_verbose = 0;
static FILE             *g_log_file = NULL;
static WCHAR             g_log_path[MAX_PATH] = L"kassandra_findings.log";

static TRACEHANDLE       g_kernel_trace_handle = INVALID_PROCESSTRACE_HANDLE;
static TRACEHANDLE       g_kernel_session_handle = 0;
static TRACEHANDLE       g_user_trace_handle   = INVALID_PROCESSTRACE_HANDLE;
static TRACEHANDLE       g_user_session_handle = 0;

static volatile LONGLONG g_event_count = 0;
static volatile LONGLONG g_kproc_count = 0;
static volatile LONGLONG g_tp_count    = 0;
static volatile LONGLONG g_tcpip_count = 0;
static volatile LONGLONG g_pf_count    = 0;
static volatile LONGLONG g_proc_count  = 0;
static volatile LONGLONG g_event_id_seq = 0;

/* ── PageFault timestamp cache ────────────────────────────────────────
 * Maps (PID, EventTimeStamp) → (VirtualAddress, opcode) so that
 * StackWalk events can be correlated back to their originating
 * PageFault_TypeGroup1 event.
 */
#define PF_CACHE_SIZE  16384
#define PF_CACHE_MASK  (PF_CACHE_SIZE - 1)

typedef struct {
    ULONG64 timestamp;
    ULONG   pid;
    ULONG64 virtual_address;
    UCHAR   opcode;
    UCHAR   used;
} pf_cache_entry_t;

static pf_cache_entry_t g_pf_cache[PF_CACHE_SIZE];

static inline ULONG pf_cache_hash(ULONG pid, ULONG64 ts) {
    ULONG64 h = ts ^ ((ULONG64)pid << 32) ^ ((ULONG64)pid);
    h = (h ^ (h >> 16)) * 0x45d9f3bULL;
    h = (h ^ (h >> 16));
    return (ULONG)(h & PF_CACHE_MASK);
}

static void pf_cache_insert(ULONG pid, ULONG64 timestamp,
                             ULONG64 vaddr, UCHAR opcode) {
    ULONG idx = pf_cache_hash(pid, timestamp);
    for (int i = 0; i < 4; i++) {
        ULONG slot = (idx + i) & PF_CACHE_MASK;
        if (!g_pf_cache[slot].used ||
            (g_pf_cache[slot].pid == pid &&
             g_pf_cache[slot].timestamp == timestamp)) {
            g_pf_cache[slot].timestamp = timestamp;
            g_pf_cache[slot].pid = pid;
            g_pf_cache[slot].virtual_address = vaddr;
            g_pf_cache[slot].opcode = opcode;
            g_pf_cache[slot].used = 1;
            return;
        }
    }
    g_pf_cache[idx].timestamp = timestamp;
    g_pf_cache[idx].pid = pid;
    g_pf_cache[idx].virtual_address = vaddr;
    g_pf_cache[idx].opcode = opcode;
    g_pf_cache[idx].used = 1;
}

static pf_cache_entry_t *pf_cache_lookup(ULONG pid, ULONG64 timestamp) {
    ULONG idx = pf_cache_hash(pid, timestamp);
    for (int i = 0; i < 4; i++) {
        ULONG slot = (idx + i) & PF_CACHE_MASK;
        if (g_pf_cache[slot].used &&
            g_pf_cache[slot].pid == pid &&
            g_pf_cache[slot].timestamp == timestamp)
            return &g_pf_cache[slot];
        if (!g_pf_cache[slot].used) break;
    }
    return NULL;
}

/* ── Stack tracing configuration (for TraceSetInformation) ──────────── */
typedef struct {
    GUID  EventGuid;
    UCHAR Type;
    UCHAR Reserved[7];
} STACK_EVENT_ID;

static LARGE_INTEGER     g_start_time;
static LARGE_INTEGER     g_perf_freq;
static HANDLE            g_console;
static WORD              g_default_attr;

/* ── ETW session names ─────────────────────────────────────────────── */
#define KERNEL_LOGGER_NAME_W  L"NT Kernel Logger"
static const WCHAR KERNEL_SESSION[] = KERNEL_LOGGER_NAME_W;
static const WCHAR USER_SESSION[]   = L"kassandra_consumer_user";

/* ── ETW kernel event class GUIDs ──────────────────────────────────── */
static const GUID ProcessGuid =
    {0x3d6fa8d0, 0xfe05, 0x11d0, {0x9d,0xda,0x00,0xc0,0x4f,0xd7,0xba,0x7c}};
static const GUID ThreadGuid =
    {0x3d6fa8d1, 0xfe05, 0x11d0, {0x9d,0xda,0x00,0xc0,0x4f,0xd7,0xba,0x7c}};
static const GUID ImageLoadGuid =
    {0x2cb15d1d, 0x5fc1, 0x11d2, {0xab,0xe1,0x00,0xa0,0xc9,0x11,0xf5,0x18}};
static const GUID TcpIpGuid =
    {0x9a280ac0, 0xc8e0, 0x11d1, {0x84,0xe2,0x00,0xc0,0x4f,0xb9,0x98,0xa2}};
static const GUID UdpIpGuid =
    {0xbf3a50c5, 0xa9c9, 0x4988, {0xa0,0x05,0x2d,0xf0,0xb7,0xc8,0x0f,0x80}};
static const GUID PageFaultGuid =
    {0x3d6fa8d3, 0xfe05, 0x11d0, {0x9d,0xda,0x00,0xc0,0x4f,0xd7,0xba,0x7c}};
static const GUID StackWalkGuid =
    {0xdef2fe46, 0x7bd6, 0x4b80, {0xbd,0x94,0xf5,0x7f,0xe2,0x0d,0x0c,0xe3}};
static const GUID SystemTraceControlGuid =
    {0x9e814aad, 0x3204, 0x11d2, {0x9a,0x82,0x00,0x60,0x08,0xa8,0x69,0x39}};

/* User-mode provider GUIDs */
/* Microsoft-Windows-Kernel-Process: {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716} */
static const GUID KernelProcessGuid =
    {0x22fb2cd6, 0x0e7b, 0x422b, {0xa0,0xc7,0x2f,0xad,0x1f,0xd0,0xe7,0x16}};
/* Microsoft-Windows-TCPIP (user-mode): same as kernel TcpIp GUID */
/* Microsoft-Windows-ThreadPool: {c861d0e2-a2c1-4d36-9f9c-970bab943a12} */
static const GUID ThreadPoolGuid =
    {0xc861d0e2, 0xa2c1, 0x4d36, {0x9f,0x9c,0x97,0x0b,0xab,0x94,0x3a,0x12}};

/* ── Forward declarations ──────────────────────────────────────────── */
static void WINAPI event_callback(PEVENT_RECORD pEvent);
static void WINAPI user_event_callback(PEVENT_RECORD pEvent);
static ULONG WINAPI buffer_callback(PEVENT_TRACE_LOGFILEW pLog);
static process_record_t *get_or_create_process(ULONG pid);
static void remove_process(ULONG pid);
static void free_process(process_record_t *proc);
static int  is_private_ip(const WCHAR *ip);
static int  is_service_port(USHORT port);
static void add_service_port(process_record_t *proc, USHORT port);
static int  is_address_in_module(process_record_t *proc, ULONG64 addr);
static void add_module(process_record_t *proc, ULONG64 base, ULONG64 size);
static void add_dynalloc(process_record_t *proc, ULONG64 addr);
static int  is_address_in_dynalloc(process_record_t *proc, ULONG64 addr);
static int  compute_level(USHORT tags);
static void build_tag_string(USHORT tags, char *buf, size_t bufsz);
static void emit_alert(process_record_t *proc, int level);
static void print_banner(void);

/* ── Utility ───────────────────────────────────────────────────────── */
static inline ULONG proc_hash(ULONG pid) {
    return pid % PROC_HASH_SIZE;
}

static void set_console_color(WORD attr) {
    SetConsoleTextAttribute(g_console, attr);
}

/* Case-insensitive wide string compare */
static int wcsicmp_local(const WCHAR *a, const WCHAR *b) {
    while (*a && *b) {
        WCHAR ca = (*a >= L'A' && *a <= L'Z') ? (*a + 32) : *a;
        WCHAR cb = (*b >= L'A' && *b <= L'Z') ? (*b + 32) : *b;
        if (ca != cb) return (int)ca - (int)cb;
        a++; b++;
    }
    return (int)*a - (int)*b;
}

/* Popcount for 32-bit balloon mask */
static int popcount32(ULONG x) {
    x = x - ((x >> 1) & 0x55555555);
    x = (x & 0x33333333) + ((x >> 2) & 0x33333333);
    return (int)(((x + (x >> 4)) & 0x0F0F0F0F) * 0x01010101 >> 24);
}

/* ── Process table operations ──────────────────────────────────────── */
static process_record_t *find_process(ULONG pid) {
    ULONG h = proc_hash(pid);
    process_record_t *p = g_proc_table[h];
    while (p) {
        if (p->pid == pid) return p;
        p = p->next;
    }
    return NULL;
}

static process_record_t *get_or_create_process(ULONG pid) {
    process_record_t *p = find_process(pid);
    if (p) return p;

    p = (process_record_t *)calloc(1, sizeof(process_record_t));
    if (!p) return NULL;
    p->pid = pid;
    wcscpy(p->image, L"<unknown>");

    ULONG h = proc_hash(pid);
    p->next = g_proc_table[h];
    g_proc_table[h] = p;
    InterlockedIncrement64(&g_proc_count);
    return p;
}

static void remove_process(ULONG pid) {
    ULONG h = proc_hash(pid);
    process_record_t **pp = &g_proc_table[h];
    while (*pp) {
        if ((*pp)->pid == pid) {
            process_record_t *doomed = *pp;
            *pp = doomed->next;
            free_process(doomed);
            InterlockedDecrement64(&g_proc_count);
            return;
        }
        pp = &(*pp)->next;
    }
}

static void free_process(process_record_t *proc) {
    module_entry_t *m = proc->modules;
    while (m) {
        module_entry_t *next = m->next;
        free(m);
        m = next;
    }
    port_entry_t *pt = proc->service_ports;
    while (pt) {
        port_entry_t *next = pt->next;
        free(pt);
        pt = next;
    }
    dynalloc_entry_t *da = proc->dynallocs;
    while (da) {
        dynalloc_entry_t *next = da->next;
        free(da);
        da = next;
    }
    free(proc);
}

/* ── Module tracking ───────────────────────────────────────────────── */
static void add_module(process_record_t *proc, ULONG64 base, ULONG64 size) {
    /* Deduplicate */
    module_entry_t *existing = proc->modules;
    while (existing) {
        if (existing->base == base) return;
        existing = existing->next;
    }
    module_entry_t *m = (module_entry_t *)malloc(sizeof(module_entry_t));
    if (!m) return;
    m->base = base;
    m->size = size;
    m->next = proc->modules;
    proc->modules = m;
    proc->module_count++;
}

static int is_address_in_module(process_record_t *proc, ULONG64 addr) {
    module_entry_t *m = proc->modules;
    while (m) {
        if (addr >= m->base && addr < m->base + m->size)
            return 1;
        m = m->next;
    }
    return 0;
}

/* ── Dynamic allocation tracking (pages touched by dynamic code) ──── */
static void add_dynalloc(process_record_t *proc, ULONG64 addr) {
    ULONG64 page = addr & ~0xFFFULL;
    dynalloc_entry_t *d = proc->dynallocs;
    while (d) {
        if (d->page_base == page) return;
        d = d->next;
    }
    d = (dynalloc_entry_t *)malloc(sizeof(dynalloc_entry_t));
    if (!d) return;
    d->page_base = page;
    d->next = proc->dynallocs;
    proc->dynallocs = d;
}

static int is_address_in_dynalloc(process_record_t *proc, ULONG64 addr) {
    ULONG64 page = addr & ~0xFFFULL;
    dynalloc_entry_t *d = proc->dynallocs;
    while (d) {
        if (d->page_base == page) return 1;
        d = d->next;
    }
    return 0;
}

/* ── DLL balloon check: match against 28 security DLLs ────────────── */
static int check_balloon_dll(process_record_t *proc, const WCHAR *dll_name) {
    const WCHAR *slash = wcsrchr(dll_name, L'\\');
    const WCHAR *name = slash ? slash + 1 : dll_name;

    for (int i = 0; i < NUM_BALLOON_DLLS; i++) {
        if (wcsicmp_local(name, BALLOON_DLLS[i]) == 0) {
            ULONG bit = 1U << i;
            if (!(proc->balloon_mask & bit)) {
                proc->balloon_mask |= bit;
                if (popcount32(proc->balloon_mask) >= BALLOON_THRESHOLD)
                    return 1;
            }
            return 0;
        }
    }
    return 0;
}

/* ── Service port tracking ─────────────────────────────────────────── */
static int is_service_port(USHORT port) {
    for (int i = 0; i < NUM_SERVICE_PORTS; i++) {
        if (SERVICE_PORTS[i] == port) return 1;
    }
    return 0;
}

static void add_service_port(process_record_t *proc, USHORT port) {
    port_entry_t *p = proc->service_ports;
    while (p) {
        if (p->port == port) return;
        p = p->next;
    }
    p = (port_entry_t *)malloc(sizeof(port_entry_t));
    if (!p) return;
    p->port = port;
    p->next = proc->service_ports;
    proc->service_ports = p;
    proc->service_port_count++;
}

/* ── Private IP check ──────────────────────────────────────────────── */
static int is_private_ip(const WCHAR *ip) {
    if (!ip) return 0;
    if (wcsncmp(ip, L"10.", 3) == 0) return 1;
    if (wcsncmp(ip, L"192.168.", 8) == 0) return 1;
    if (wcsncmp(ip, L"127.", 4) == 0) return 1;
    if (wcsncmp(ip, L"172.", 4) == 0) {
        int octet2 = 0;
        const WCHAR *p = ip + 4;
        while (*p && *p != L'.') {
            octet2 = octet2 * 10 + (*p - L'0');
            p++;
        }
        if (octet2 >= 16 && octet2 <= 31) return 1;
    }
    return 0;
}

/* ── Level determination (combinatorial severity from tag bitmask) ──
 *
 * Two-phase approach matching the original binary (RVA 0x23720):
 *   Phase 1: compute base level from {net,balloon,hi_ports,dyn_code}
 *   Phase 2: escalate based on tp_callback / dynamic_code_nested
 *
 * Original has NO critical level — HIGH(4) is the maximum.
 * Single tags alone always produce NONE (no alert).
 */
static int compute_level(USHORT tags) {
    if (tags == 0) return LEVEL_NONE;

    int net_pub     = !!(tags & TAG_NET_PUBLIC);
    int net_priv    = !!(tags & TAG_NET_PRIVATE);
    int net_tunnel  = !!(tags & TAG_NET_TUNNEL);
    int dyn_code    = !!(tags & TAG_DYNAMIC_CODE);
    int dyn_nested  = !!(tags & TAG_DYNAMIC_CODE_NESTED);
    int sleep_tp    = !!(tags & TAG_SLEEP_TP_CALLBACK);
    int proxy_tp    = !!(tags & TAG_PROXY_TP_CALLBACK);
    int mod_balloon = !!(tags & TAG_MODULE_BALLOON);
    int hi_ports    = !!(tags & TAG_HIGH_SERVICE_PORTS);
    int tp_flag     = sleep_tp || proxy_tp;

    /* ── Phase 1: base level from network/balloon/ports/dyncode ── */
    int base = LEVEL_NONE;

    /* MEDIUM base (4-tag combos) */
    if (mod_balloon && dyn_code && net_tunnel && (net_pub || net_priv))
        base = LEVEL_MEDIUM;

    /* LOW base (net+dyn pairs, 3-tag combos, hi_ports pairs) */
    if (base < LEVEL_LOW) {
        if ((net_pub && dyn_code) ||
            (net_priv && dyn_code) ||
            (net_pub && dyn_code && net_tunnel) ||
            (net_priv && dyn_code && net_tunnel) ||
            (mod_balloon && dyn_code && net_pub) ||
            (mod_balloon && net_pub && net_priv) ||
            (hi_ports && dyn_code) ||
            (hi_ports && mod_balloon) ||
            (hi_ports && net_tunnel))
            base = LEVEL_LOW;
    }

    /* INFO base (balloon pairs, net_pub+net_priv) */
    if (base < LEVEL_INFO) {
        if ((mod_balloon && dyn_code) ||
            (mod_balloon && net_pub) ||
            (mod_balloon && net_priv) ||
            (net_pub && net_priv))
            base = LEVEL_INFO;
    }

    /* ── Phase 2: escalate via tp_callback / nested ──────────── */
    int level = base;

    if (base >= LEVEL_LOW) {
        if (tp_flag || dyn_nested)
            level = LEVEL_HIGH;
    } else if (base == LEVEL_INFO) {
        if (tp_flag && dyn_nested)
            level = LEVEL_HIGH;
        else if (tp_flag || dyn_nested)
            level = LEVEL_MEDIUM;
    } else {
        /* base == NONE */
        if (tp_flag && dyn_code && dyn_nested)
            level = LEVEL_HIGH;
        else if (tp_flag && dyn_code)
            level = LEVEL_MEDIUM;
    }

    return level;
}

/* ── Build comma-separated tag string ──────────────────────────────── */
static void build_tag_string(USHORT tags, char *buf, size_t bufsz) {
    buf[0] = '\0';
    if (tags == 0) { strncpy(buf, "NONE", bufsz); return; }

    int first = 1;
#define APPEND_TAG(flag, name) do { \
    if (tags & (flag)) { \
        if (!first) strncat(buf, " | ", bufsz - strlen(buf) - 1); \
        strncat(buf, (name), bufsz - strlen(buf) - 1); \
        first = 0; \
    } \
} while(0)

    APPEND_TAG(TAG_NET_PUBLIC,          "net_public");
    APPEND_TAG(TAG_NET_PRIVATE,         "net_private");
    APPEND_TAG(TAG_NET_TUNNEL,          "net_tunnel");
    APPEND_TAG(TAG_DYNAMIC_CODE,        "dynamic_code");
    APPEND_TAG(TAG_DYNAMIC_CODE_NESTED, "dynamic_code_nested");
    APPEND_TAG(TAG_SLEEP_TP_CALLBACK,   "sleep_tp_callback");
    APPEND_TAG(TAG_PROXY_TP_CALLBACK,   "proxy_tp_callback");
    APPEND_TAG(TAG_MODULE_BALLOON,      "module_balloon");
    APPEND_TAG(TAG_HIGH_SERVICE_PORTS,  "high_num_of_service_ports");
#undef APPEND_TAG
}

/* ── Alert emission ────────────────────────────────────────────────── */
static const char *level_name(int level) {
    switch (level) {
    case LEVEL_NONE:     return "NONE";
    case LEVEL_INFO:     return "INFO";
    case LEVEL_LOW:      return "LOW";
    case LEVEL_MEDIUM:   return "MEDIUM";
    case LEVEL_HIGH:     return "HIGH";
    default:             return "UNKNOWN";
    }
}

static WORD level_color(int level) {
    switch (level) {
    case LEVEL_INFO:     return COLOR_INFO;
    case LEVEL_LOW:      return COLOR_LOW;
    case LEVEL_MEDIUM:   return COLOR_MEDIUM;
    case LEVEL_HIGH:     return COLOR_HIGH;
    default:             return COLOR_DEFAULT;
    }
}

static void emit_alert(process_record_t *proc, int level) {
    if (level == LEVEL_NONE) return;

    char tag_buf[512];
    build_tag_string(proc->tags, tag_buf, sizeof(tag_buf));

    char image_narrow[260];
    WideCharToMultiByte(CP_OEMCP, 0, proc->image, -1,
                        image_narrow, sizeof(image_narrow), NULL, NULL);

    EnterCriticalSection(&g_output_lock);

    set_console_color(level_color(level));
    printf("[%s] pid=%u image=%s level=%s tags=[%s]\n",
           level_name(level), proc->pid, image_narrow,
           level_name(level), tag_buf);
    set_console_color(g_default_attr);

    /* Write LOW+ findings to log file */
    if (g_log_file && level >= LEVEL_LOW) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        fprintf(g_log_file,
                "%04d-%02d-%02d %02d:%02d:%02d  [%s] pid=%u image=%s tags=[%s]\n",
                st.wYear, st.wMonth, st.wDay,
                st.wHour, st.wMinute, st.wSecond,
                level_name(level), proc->pid, image_narrow, tag_buf);
        fflush(g_log_file);
    }

    LeaveCriticalSection(&g_output_lock);
}

/* ── Tag name for per-tag info messages ────────────────────────────── */
static const char *tag_display_name(USHORT tag) {
    switch (tag) {
    case TAG_NET_PUBLIC:          return "public network";
    case TAG_NET_PRIVATE:         return "private network";
    case TAG_NET_TUNNEL:          return "network tunnel";
    case TAG_DYNAMIC_CODE:        return "Dynamic code";
    case TAG_DYNAMIC_CODE_NESTED: return "Nested dynamic code";
    case TAG_SLEEP_TP_CALLBACK:   return "Sleep TP callback";
    case TAG_PROXY_TP_CALLBACK:   return "Proxy TP callback";
    case TAG_MODULE_BALLOON:      return "Module balloon";
    case TAG_HIGH_SERVICE_PORTS:  return "High service ports";
    default:                      return "unknown";
    }
}

/* ── Try to apply a tag and emit alert only on level INCREASE ──────── */
static void try_tag(process_record_t *proc, USHORT new_tag) {
    if (proc->tags & new_tag) return;

    proc->tags |= new_tag;

    /* No detections during rundown (baseline collection) */
    if (g_rundown_active) return;

    /* Per-tag info message (matches original output format) */
    {
        char image_narrow[260];
        WideCharToMultiByte(CP_OEMCP, 0, proc->image, -1,
                            image_narrow, sizeof(image_narrow), NULL, NULL);
        EnterCriticalSection(&g_output_lock);
        set_console_color(COLOR_INFO);
        printf("[info] %s:%u %s tag added\n",
               image_narrow, proc->pid, tag_display_name(new_tag));
        set_console_color(g_default_attr);
        LeaveCriticalSection(&g_output_lock);
    }

    int new_level = compute_level(proc->tags);
    if (new_level > proc->emitted_level) {
        proc->emitted_level = new_level;
        emit_alert(proc, new_level);
    }
}

/* ── TDH property extraction helpers ───────────────────────────────── */
static BOOL get_event_property_uint32(PEVENT_RECORD pEvent,
                                      PTRACE_EVENT_INFO pInfo,
                                      const WCHAR *propName,
                                      ULONG *out) {
    for (ULONG i = 0; i < pInfo->TopLevelPropertyCount; i++) {
        WCHAR *name = (WCHAR *)((BYTE *)pInfo +
                      pInfo->EventPropertyInfoArray[i].NameOffset);
        if (wcscmp(name, propName) == 0) {
            PROPERTY_DATA_DESCRIPTOR desc;
            desc.PropertyName = (ULONGLONG)name;
            desc.ArrayIndex   = ULONG_MAX;
            desc.Reserved     = 0;
            ULONG size = 0;
            if (TdhGetPropertySize(pEvent, 0, NULL, 1, &desc, &size) == ERROR_SUCCESS) {
                if (size == sizeof(ULONG)) {
                    return TdhGetProperty(pEvent, 0, NULL, 1, &desc,
                                          size, (BYTE *)out) == ERROR_SUCCESS;
                } else if (size == sizeof(USHORT)) {
                    USHORT v = 0;
                    if (TdhGetProperty(pEvent, 0, NULL, 1, &desc,
                                       size, (BYTE *)&v) == ERROR_SUCCESS) {
                        *out = v;
                        return TRUE;
                    }
                }
            }
            return FALSE;
        }
    }
    return FALSE;
}

static BOOL get_event_property_uint64(PEVENT_RECORD pEvent,
                                      PTRACE_EVENT_INFO pInfo,
                                      const WCHAR *propName,
                                      ULONG64 *out) {
    for (ULONG i = 0; i < pInfo->TopLevelPropertyCount; i++) {
        WCHAR *name = (WCHAR *)((BYTE *)pInfo +
                      pInfo->EventPropertyInfoArray[i].NameOffset);
        if (wcscmp(name, propName) == 0) {
            PROPERTY_DATA_DESCRIPTOR desc;
            desc.PropertyName = (ULONGLONG)name;
            desc.ArrayIndex   = ULONG_MAX;
            desc.Reserved     = 0;
            ULONG size = 0;
            if (TdhGetPropertySize(pEvent, 0, NULL, 1, &desc, &size) == ERROR_SUCCESS) {
                if (size == sizeof(ULONG64)) {
                    return TdhGetProperty(pEvent, 0, NULL, 1, &desc,
                                          size, (BYTE *)out) == ERROR_SUCCESS;
                } else if (size == sizeof(ULONG)) {
                    ULONG v = 0;
                    if (TdhGetProperty(pEvent, 0, NULL, 1, &desc,
                                       size, (BYTE *)&v) == ERROR_SUCCESS) {
                        *out = v;
                        return TRUE;
                    }
                }
            }
            return FALSE;
        }
    }
    return FALSE;
}

static BOOL get_event_property_string(PEVENT_RECORD pEvent,
                                      PTRACE_EVENT_INFO pInfo,
                                      const WCHAR *propName,
                                      WCHAR *out, ULONG outChars) {
    for (ULONG i = 0; i < pInfo->TopLevelPropertyCount; i++) {
        WCHAR *name = (WCHAR *)((BYTE *)pInfo +
                      pInfo->EventPropertyInfoArray[i].NameOffset);
        if (wcscmp(name, propName) == 0) {
            PROPERTY_DATA_DESCRIPTOR desc;
            desc.PropertyName = (ULONGLONG)name;
            desc.ArrayIndex   = ULONG_MAX;
            desc.Reserved     = 0;
            ULONG size = 0;
            if (TdhGetPropertySize(pEvent, 0, NULL, 1, &desc, &size) != ERROR_SUCCESS || size == 0)
                return FALSE;

            USHORT inType = pInfo->EventPropertyInfoArray[i].nonStructType.InType;

            if (inType == TDH_INTYPE_ANSISTRING) {
                char ansi[520];
                if (size > sizeof(ansi)) size = sizeof(ansi);
                if (TdhGetProperty(pEvent, 0, NULL, 1, &desc,
                                   size, (BYTE *)ansi) == ERROR_SUCCESS) {
                    ansi[size - 1] = '\0';
                    MultiByteToWideChar(CP_ACP, 0, ansi, -1, out, outChars);
                    return TRUE;
                }
            } else {
                ULONG outBytes = outChars * sizeof(WCHAR);
                if (size <= outBytes) {
                    if (TdhGetProperty(pEvent, 0, NULL, 1, &desc,
                                       size, (BYTE *)out) == ERROR_SUCCESS) {
                        out[size / sizeof(WCHAR)] = L'\0';
                        return TRUE;
                    }
                }
            }
            return FALSE;
        }
    }
    return FALSE;
}

/* Helper: parse TDH info for an event (allocates, caller must free) */
static PTRACE_EVENT_INFO alloc_event_info(PEVENT_RECORD pEvent) {
    ULONG bufSize = 0;
    if (TdhGetEventInformation(pEvent, 0, NULL, NULL, &bufSize) !=
        ERROR_INSUFFICIENT_BUFFER)
        return NULL;
    PTRACE_EVENT_INFO pInfo = (PTRACE_EVENT_INFO)malloc(bufSize);
    if (!pInfo) return NULL;
    if (TdhGetEventInformation(pEvent, 0, NULL, pInfo, &bufSize) != ERROR_SUCCESS) {
        free(pInfo);
        return NULL;
    }
    return pInfo;
}

/* ── Process events ────────────────────────────────────────────────── */
static void handle_process_event(PEVENT_RECORD pEvent) {
    InterlockedIncrement64(&g_kproc_count);

    UCHAR opcode = pEvent->EventHeader.EventDescriptor.Opcode;

    if (opcode == 1 || opcode == 3) {
        PTRACE_EVENT_INFO pInfo = alloc_event_info(pEvent);
        if (!pInfo) return;

        ULONG pid = 0;
        get_event_property_uint32(pEvent, pInfo, L"ProcessId", &pid);
        if (pid == 0) { free(pInfo); return; }

        EnterCriticalSection(&g_proc_lock);
        process_record_t *proc = get_or_create_process(pid);
        if (proc) {
            WCHAR imgName[260] = {0};
            if (get_event_property_string(pEvent, pInfo, L"ImageFileName",
                                          imgName, 260) && imgName[0]) {
                WCHAR *slash = wcsrchr(imgName, L'\\');
                wcsncpy(proc->image, slash ? slash + 1 : imgName, 259);
            }
        }
        LeaveCriticalSection(&g_proc_lock);
        free(pInfo);

    } else if (opcode == 2 || opcode == 4) {
        PTRACE_EVENT_INFO pInfo = alloc_event_info(pEvent);
        if (!pInfo) return;
        ULONG pid = 0;
        get_event_property_uint32(pEvent, pInfo, L"ProcessId", &pid);
        if (pid != 0) {
            EnterCriticalSection(&g_proc_lock);
            remove_process(pid);
            LeaveCriticalSection(&g_proc_lock);
        }
        free(pInfo);
    }
}

/* ── Image Load events ─────────────────────────────────────────────── */
static void handle_image_load_event(PEVENT_RECORD pEvent) {
    UCHAR opcode = pEvent->EventHeader.EventDescriptor.Opcode;
    if (opcode != 10) return;  /* only real-time loads, not DCStart/rundown */

    PTRACE_EVENT_INFO pInfo = alloc_event_info(pEvent);
    if (!pInfo) return;

    ULONG pid = 0;
    ULONG64 imageBase = 0, imageSize = 0;
    get_event_property_uint32(pEvent, pInfo, L"ProcessId", &pid);
    get_event_property_uint64(pEvent, pInfo, L"ImageBase", &imageBase);
    get_event_property_uint64(pEvent, pInfo, L"ImageSize", &imageSize);

    if (pid == 0 || imageBase == 0) { free(pInfo); return; }

    WCHAR fileName[520] = {0};
    get_event_property_string(pEvent, pInfo, L"FileName", fileName, 520);

    EnterCriticalSection(&g_proc_lock);
    process_record_t *proc = get_or_create_process(pid);
    if (proc) {
        add_module(proc, imageBase, imageSize);

        /* DLL balloon: check against 28 security DLLs */
        if (fileName[0] && check_balloon_dll(proc, fileName)) {
            try_tag(proc, TAG_MODULE_BALLOON);
        }

        /* Update image name if still unknown */
        if (proc->image[0] == L'<' && fileName[0]) {
            WCHAR *slash = wcsrchr(fileName, L'\\');
            wcsncpy(proc->image, slash ? slash + 1 : fileName, 259);
        }
    }
    LeaveCriticalSection(&g_proc_lock);
    free(pInfo);
}

/* ── TCP/IP events ─────────────────────────────────────────────────── */
static void handle_tcpip_event(PEVENT_RECORD pEvent) {
    InterlockedIncrement64(&g_tcpip_count);

    PTRACE_EVENT_INFO pInfo = alloc_event_info(pEvent);
    if (!pInfo) return;

    ULONG pid = 0, dport = 0;
    get_event_property_uint32(pEvent, pInfo, L"PID", &pid);
    if (pid == 0)
        get_event_property_uint32(pEvent, pInfo, L"connid", &pid);
    get_event_property_uint32(pEvent, pInfo, L"dport", &dport);

    if (pid == 0) { free(pInfo); return; }

    WCHAR daddr[64] = {0};
    BOOL got_addr = get_event_property_string(pEvent, pInfo, L"daddr",
                                               daddr, 64);
    if (!got_addr) {
        ULONG raw_addr = 0;
        if (get_event_property_uint32(pEvent, pInfo, L"daddr", &raw_addr)) {
            struct in_addr addr;
            addr.s_addr = raw_addr;
            InetNtopW(AF_INET, &addr, daddr, 64);
            got_addr = TRUE;
        }
    }

    EnterCriticalSection(&g_proc_lock);
    process_record_t *proc = get_or_create_process(pid);
    if (proc && got_addr && daddr[0]) {
        if (is_private_ip(daddr)) {
            try_tag(proc, TAG_NET_PRIVATE);
        } else {
            try_tag(proc, TAG_NET_PUBLIC);
        }

        if ((proc->tags & TAG_NET_PUBLIC) && (proc->tags & TAG_NET_PRIVATE))
            try_tag(proc, TAG_NET_TUNNEL);

        USHORT port = (USHORT)(dport & 0xFFFF);
        if (port != 0 && is_service_port(port)) {
            add_service_port(proc, port);
            if (proc->service_port_count >= SERVICE_PORT_THRESHOLD)
                try_tag(proc, TAG_HIGH_SERVICE_PORTS);
        }
    }
    LeaveCriticalSection(&g_proc_lock);
    free(pInfo);
}

/* ── PageFault_TypeGroup1 events ──────────────────────────────────────
 *
 * Cache DemandZeroFault (11), CopyOnWrite (12), TransitionFault (10)
 * events keyed by (PID, EventTimeStamp).  StackWalk events that arrive
 * shortly after use EventTimeStamp to correlate back to these.
 *
 * Raw layout on x64: VirtualAddress(8) + ProgramCounter(8) = 16 bytes
 */
static void handle_pagefault_event(PEVENT_RECORD pEvent) {
    InterlockedIncrement64(&g_pf_count);

    UCHAR opcode = pEvent->EventHeader.EventDescriptor.Opcode;

    if (opcode != 10 && opcode != 11 && opcode != 12) return;

    if (!pEvent->UserData || pEvent->UserDataLength < 16) return;

    ULONG pid = pEvent->EventHeader.ProcessId;
    if (pid <= 4) return;

    ULONG64 vaddr = *(ULONG64 *)pEvent->UserData;
    if (vaddr == 0 || vaddr >= 0xFFFF000000000000ULL) return;

    pf_cache_insert(pid, pEvent->EventHeader.TimeStamp.QuadPart,
                    vaddr, opcode);
}

/* ── StackWalk events ─────────────────────────────────────────────────
 *
 * Correlated with PageFault_TypeGroup1 events via EventTimeStamp.
 *
 * For DemandZeroFault / CopyOnWrite (opcodes 11, 12):
 *   - Broken callstack (frame outside any module) → TAG_DYNAMIC_CODE
 *   - Record the faulted VirtualAddress in dynalloc map (these are
 *     pages being written/allocated by dynamic code)
 *
 * For TransitionFault (opcode 10):
 *   - If any callstack frame falls in the dynalloc map → code executing
 *     from a page that dynamic code previously wrote to
 *   - This is nested dynamic code → TAG_DYNAMIC_CODE_NESTED
 *
 * Raw layout: EventTimeStamp(8) + StackProcess(4) + StackThread(4)
 *             + Stack[N] where each frame is pointer-sized (8 on x64)
 */
static void handle_stackwalk_event(PEVENT_RECORD pEvent) {
    if (g_rundown_active) return;
    if (!pEvent->UserData || pEvent->UserDataLength < 24) return;

    BYTE *data = (BYTE *)pEvent->UserData;
    ULONG64 eventTimestamp = *(ULONG64 *)data;
    ULONG stackProcess = *(ULONG *)(data + 8);

    if (stackProcess <= 4) return;

    int frameBytes = (int)pEvent->UserDataLength - 16;
    if (frameBytes <= 0) return;
    int numFrames = frameBytes / sizeof(ULONG_PTR);
    ULONG_PTR *frames = (ULONG_PTR *)(data + 16);

    pf_cache_entry_t *cached = pf_cache_lookup(stackProcess, eventTimestamp);
    if (!cached) return;

    EnterCriticalSection(&g_proc_lock);
    process_record_t *proc = find_process(stackProcess);
    if (!proc || !proc->modules) {
        LeaveCriticalSection(&g_proc_lock);
        return;
    }

    if (cached->opcode == 11 || cached->opcode == 12) {
        int has_dynamic_frame = 0;
        for (int i = 0; i < numFrames; i++) {
            ULONG64 frame = (ULONG64)frames[i];
            if (frame == 0) continue;
            if (frame >= 0xFFFF000000000000ULL) continue;
            if (!is_address_in_module(proc, frame) &&
                !is_address_in_system_dlls(frame)) {
                has_dynamic_frame = 1;
                break;
            }
        }
        if (has_dynamic_frame) {
            try_tag(proc, TAG_DYNAMIC_CODE);
            add_dynalloc(proc, cached->virtual_address);
        }
    } else if (cached->opcode == 10) {
        for (int i = 0; i < numFrames; i++) {
            ULONG64 frame = (ULONG64)frames[i];
            if (frame == 0) continue;
            if (frame >= 0xFFFF000000000000ULL) continue;
            if (is_address_in_dynalloc(proc, frame)) {
                try_tag(proc, TAG_DYNAMIC_CODE_NESTED);
                break;
            }
        }
    }

    LeaveCriticalSection(&g_proc_lock);
}

/* ── ThreadPool CBEnqueue events ──────────────────────────────────────
 *
 * Monitor TP_V2_CBEnqueue (opcode 34) from the ThreadPool provider.
 * Resolve CallbackFunction against ntdll/kernel32/kernelbase exports
 * to detect sleep-masking and module-proxying callbacks.
 */
static void handle_threadpool_event(PEVENT_RECORD pEvent) {
    InterlockedIncrement64(&g_tp_count);

    UCHAR opcode = pEvent->EventHeader.EventDescriptor.Opcode;
    if (opcode != 34) return;

    ULONG pid = pEvent->EventHeader.ProcessId;
    if (pid <= 4) return;

    ULONG64 callbackFunc = 0;

    PTRACE_EVENT_INFO pInfo = alloc_event_info(pEvent);
    if (pInfo) {
        get_event_property_uint64(pEvent, pInfo, L"CallbackFunction",
                                  &callbackFunc);
        free(pInfo);
    }

    if (callbackFunc == 0 || callbackFunc >= 0xFFFF000000000000ULL)
        return;

    const char *funcName = resolve_address_in_system_dlls(callbackFunc);
    if (!funcName) return;

    ULONGLONG h = fnv1a_hash(funcName);

    EnterCriticalSection(&g_proc_lock);
    process_record_t *proc = get_or_create_process(pid);
    if (proc) {
        if (hash_set_contains(&g_sleep_hashes, h))
            try_tag(proc, TAG_SLEEP_TP_CALLBACK);
        else if (hash_set_contains(&g_proxy_hashes, h))
            try_tag(proc, TAG_PROXY_TP_CALLBACK);
    }
    LeaveCriticalSection(&g_proc_lock);
}

/* ── Main kernel event dispatch ────────────────────────────────────── */
static void WINAPI event_callback(PEVENT_RECORD pEvent) {
    if (!pEvent || !g_running) return;
    InterlockedIncrement64(&g_event_count);

    GUID *provider = &pEvent->EventHeader.ProviderId;

    if (IsEqualGUID(provider, &ProcessGuid))
        handle_process_event(pEvent);
    else if (IsEqualGUID(provider, &ImageLoadGuid))
        handle_image_load_event(pEvent);
    else if (IsEqualGUID(provider, &TcpIpGuid) ||
             IsEqualGUID(provider, &UdpIpGuid))
        handle_tcpip_event(pEvent);
    else if (IsEqualGUID(provider, &PageFaultGuid))
        handle_pagefault_event(pEvent);
    else if (IsEqualGUID(provider, &StackWalkGuid))
        handle_stackwalk_event(pEvent);
}

/* ── User-mode event dispatch (thread pool + kernel-process events) ── */
static void WINAPI user_event_callback(PEVENT_RECORD pEvent) {
    if (!pEvent || !g_running) return;
    InterlockedIncrement64(&g_event_count);

    if (IsEqualGUID(&pEvent->EventHeader.ProviderId, &KernelProcessGuid)) {
        handle_process_event(pEvent);
    } else if (IsEqualGUID(&pEvent->EventHeader.ProviderId, &TcpIpGuid)) {
        handle_tcpip_event(pEvent);
    } else if (IsEqualGUID(&pEvent->EventHeader.ProviderId,
                            &ThreadPoolGuid)) {
        handle_threadpool_event(pEvent);
    }
}

static ULONG WINAPI buffer_callback(PEVENT_TRACE_LOGFILEW pLog) {
    return g_running ? TRUE : FALSE;
}

/* ── Banner / status line ──────────────────────────────────────────── */
static void print_banner(void) {
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    LONGLONG elapsed = (now.QuadPart - g_start_time.QuadPart) /
                       g_perf_freq.QuadPart;
    int hours   = (int)(elapsed / 3600);
    int minutes = (int)((elapsed % 3600) / 60);
    int seconds = (int)(elapsed % 60);

    EnterCriticalSection(&g_output_lock);

    /* ANSI: save cursor, move to 1,1 */
    printf("\x1b[s\x1b[1;1H");

    set_console_color(COLOR_BANNER);
    printf("  _  __    _    ____ ____    _    _   _ ____  ____      _      \n");
    printf(" | |/ /   / \\  / ___/ ___|  / \\  | \\ | |  _ \\|  _ \\    / \\     \n");
    printf(" | ' /   / _ \\ \\___ \\___ \\ / _ \\ |  \\| | | | | |_) |  / _ \\    \n");
    printf(" | . \\  / ___ \\ ___) |__) / ___ \\| |\\  | |_| |  _ <  / ___ \\   \n");
    printf(" |_|\\_\\/_/   \\_\\____/____/_/   \\_\\_| \\_|____/|_| \\_\\/_/   \\_\\  \n");
    printf("------------------------------------------------------------------\n");
    set_console_color(0x0F);
    printf(" uptime=%02d:%02d:%02d  procs=%lld  events=%lld  "
           "(kproc=%lld tp=%lld tcpip=%lld pf=%lld)   \n",
           hours, minutes, seconds,
           g_proc_count, g_event_count,
           g_kproc_count, g_tp_count, g_tcpip_count, g_pf_count);
    set_console_color(g_default_attr);

    /* ANSI: restore cursor */
    printf("\x1b[u");

    LeaveCriticalSection(&g_output_lock);
}

/* ── Ctrl-C handler ────────────────────────────────────────────────── */
static BOOL WINAPI ctrl_handler(DWORD ctrlType) {
    if (ctrlType == CTRL_C_EVENT || ctrlType == CTRL_BREAK_EVENT) {
        InterlockedExchange(&g_running, 0);
        return TRUE;
    }
    return FALSE;
}

/* ── ETW trace pump thread ─────────────────────────────────────────── */
static DWORD WINAPI trace_pump(LPVOID param) {
    TRACEHANDLE handle = *(TRACEHANDLE *)param;
    ProcessTrace(&handle, 1, NULL, NULL);
    return 0;
}

/* ── Stop a named ETW session ──────────────────────────────────────── */
static void stop_named_session(const WCHAR *name) {
    ULONG propSize = sizeof(EVENT_TRACE_PROPERTIES) + 1024;
    EVENT_TRACE_PROPERTIES *p = (EVENT_TRACE_PROPERTIES *)calloc(1, propSize);
    if (!p) return;
    p->Wnode.BufferSize = propSize;
    p->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    wcscpy((WCHAR *)((BYTE *)p + p->LoggerNameOffset), name);
    ControlTraceW(0, name, p, EVENT_TRACE_CONTROL_STOP);
    free(p);
}

/* ── Kernel trace session setup ────────────────────────────────────── */
static int start_kernel_trace(void) {
    stop_named_session(KERNEL_SESSION);

    ULONG bufSize = sizeof(EVENT_TRACE_PROPERTIES) + 1024;
    EVENT_TRACE_PROPERTIES *pProps = (EVENT_TRACE_PROPERTIES *)calloc(1, bufSize);
    if (!pProps) return -1;

    pProps->Wnode.BufferSize = bufSize;
    pProps->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    pProps->Wnode.ClientContext = 1;
    pProps->Wnode.Guid = SystemTraceControlGuid;
    pProps->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    pProps->BufferSize = 256;
    pProps->MinimumBuffers = 64;
    pProps->MaximumBuffers = 128;
    pProps->FlushTimer = 1;
    pProps->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    pProps->EnableFlags = EVENT_TRACE_FLAG_PROCESS |
                          EVENT_TRACE_FLAG_THREAD |
                          EVENT_TRACE_FLAG_IMAGE_LOAD |
                          EVENT_TRACE_FLAG_NETWORK_TCPIP |
                          EVENT_TRACE_FLAG_MEMORY_PAGE_FAULTS;

    ULONG status = StartTraceW(&g_kernel_session_handle, KERNEL_SESSION, pProps);
    if (status != ERROR_SUCCESS) {
        if (status == ERROR_ACCESS_DENIED)
            fprintf(stderr, "Error: Need to be an admin "
                    "(requires SeSystemProfilePrivilege)\n");
        else
            fprintf(stderr, "Error: StartTraceW (kernel) failed: %lu\n", status);
        free(pProps);
        return -1;
    }
    free(pProps);

    /* Enable stack collection for PageFault events we correlate with */
    STACK_EVENT_ID stackIds[3];
    memset(stackIds, 0, sizeof(stackIds));
    stackIds[0].EventGuid = PageFaultGuid;
    stackIds[0].Type = 10;  /* TransitionFault */
    stackIds[1].EventGuid = PageFaultGuid;
    stackIds[1].Type = 11;  /* DemandZeroFault */
    stackIds[2].EventGuid = PageFaultGuid;
    stackIds[2].Type = 12;  /* CopyOnWrite */

    status = TraceSetInformation(g_kernel_session_handle,
                                 (TRACE_INFO_CLASS)3,
                                 stackIds, sizeof(stackIds));
    if (status != ERROR_SUCCESS) {
        fprintf(stderr, "Warning: TraceSetInformation (stack tracing) "
                "failed: %lu\n", status);
    }

    EVENT_TRACE_LOGFILEW logFile;
    ZeroMemory(&logFile, sizeof(logFile));
    logFile.LoggerName = (LPWSTR)KERNEL_SESSION;
    logFile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME |
                               PROCESS_TRACE_MODE_EVENT_RECORD;
    logFile.EventRecordCallback = event_callback;
    logFile.BufferCallback = buffer_callback;

    g_kernel_trace_handle = OpenTraceW(&logFile);
    if (g_kernel_trace_handle == INVALID_PROCESSTRACE_HANDLE) {
        fprintf(stderr, "Error: OpenTraceW (kernel) failed: %lu\n", GetLastError());
        return -1;
    }
    return 0;
}

/* ── User trace session setup ──────────────────────────────────────── */
static int start_user_trace(void) {
    stop_named_session(USER_SESSION);

    ULONG bufSize = sizeof(EVENT_TRACE_PROPERTIES) + 1024;
    EVENT_TRACE_PROPERTIES *pProps = (EVENT_TRACE_PROPERTIES *)calloc(1, bufSize);
    if (!pProps) return -1;

    pProps->Wnode.BufferSize = bufSize;
    pProps->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    pProps->Wnode.ClientContext = 1;
    pProps->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    pProps->BufferSize = 64;
    pProps->MinimumBuffers = 16;
    pProps->MaximumBuffers = 64;
    pProps->FlushTimer = 1;
    pProps->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    ULONG status = StartTraceW(&g_user_session_handle, USER_SESSION, pProps);
    if (status != ERROR_SUCCESS) {
        fprintf(stderr, "Warning: StartTraceW (user) failed: %lu\n", status);
        free(pProps);
        return -1;
    }
    free(pProps);

    /* Enable Microsoft-Windows-Kernel-Process provider */
    status = EnableTraceEx2(g_user_session_handle, &KernelProcessGuid,
                            EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                            TRACE_LEVEL_VERBOSE,
                            0x10, /* WINEVENT_KEYWORD_PROCESS */
                            0, 0, NULL);
    if (status != ERROR_SUCCESS) {
        fprintf(stderr, "Warning: EnableTraceEx2 (Kernel-Process) failed: %lu\n",
                status);
    }

    /* Enable Microsoft-Windows-TCPIP provider */
    status = EnableTraceEx2(g_user_session_handle, &TcpIpGuid,
                            EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                            TRACE_LEVEL_VERBOSE,
                            0x10000, 0, 0, NULL);
    if (status != ERROR_SUCCESS) {
        /* Non-fatal: kernel TcpIp events will still work */
    }

    /* Enable Microsoft-Windows-ThreadPool provider for CB enqueue events */
    status = EnableTraceEx2(g_user_session_handle, &ThreadPoolGuid,
                            EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                            TRACE_LEVEL_VERBOSE,
                            0, 0, 0, NULL);
    if (status != ERROR_SUCCESS) {
        fprintf(stderr, "Warning: EnableTraceEx2 (ThreadPool) failed: %lu\n",
                status);
    }

    EVENT_TRACE_LOGFILEW logFile;
    ZeroMemory(&logFile, sizeof(logFile));
    logFile.LoggerName = (LPWSTR)USER_SESSION;
    logFile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME |
                               PROCESS_TRACE_MODE_EVENT_RECORD;
    logFile.EventRecordCallback = user_event_callback;
    logFile.BufferCallback = buffer_callback;

    g_user_trace_handle = OpenTraceW(&logFile);
    if (g_user_trace_handle == INVALID_PROCESSTRACE_HANDLE) {
        fprintf(stderr, "Warning: OpenTraceW (user) failed: %lu\n", GetLastError());
        return -1;
    }
    return 0;
}

/* ── Rundown: enumerate existing processes via Toolhelp32 ─────────── */
static void run_rundown(void) {
    InterlockedExchange(&g_rundown_active, 1);

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) goto done;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (pe.th32ProcessID == 0) continue;

            EnterCriticalSection(&g_proc_lock);
            process_record_t *proc = get_or_create_process(pe.th32ProcessID);
            if (proc && proc->image[0] == L'<') {
                wcsncpy(proc->image, pe.szExeFile, 259);
            }
            LeaveCriticalSection(&g_proc_lock);

            /* Enumerate modules for this process */
            HANDLE hModSnap = CreateToolhelp32Snapshot(
                TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                pe.th32ProcessID);
            if (hModSnap != INVALID_HANDLE_VALUE) {
                MODULEENTRY32W me;
                me.dwSize = sizeof(me);
                if (Module32FirstW(hModSnap, &me)) {
                    do {
                        EnterCriticalSection(&g_proc_lock);
                        proc = find_process(pe.th32ProcessID);
                        if (proc) {
                            add_module(proc, (ULONG64)me.modBaseAddr,
                                       me.modBaseSize);
                            check_balloon_dll(proc, me.szModule);
                        }
                        LeaveCriticalSection(&g_proc_lock);
                    } while (Module32NextW(hModSnap, &me));
                }
                CloseHandle(hModSnap);
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);

    fprintf(stderr, "[info] rundown pump live\n");
    fprintf(stderr, "[info] rundown drained (%lld events)\n", g_proc_count);
    fprintf(stderr, "[info] process_tree size after rundown: %lld\n",
            g_proc_count);

done:
    InterlockedExchange(&g_rundown_active, 0);
}

/* ── Orphan cleanup ────────────────────────────────────────────────── */
static DWORD WINAPI orphan_cleanup_thread(LPVOID param) {
    (void)param;
    while (g_running) {
        Sleep(30000); /* Check every 30 seconds */
        if (!g_running) break;

        int cleaned = 0;
        EnterCriticalSection(&g_proc_lock);
        for (int i = 0; i < PROC_HASH_SIZE; i++) {
            process_record_t **pp = &g_proc_table[i];
            while (*pp) {
                process_record_t *p = *pp;
                HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,
                                           FALSE, p->pid);
                if (hProc) {
                    DWORD exitCode = 0;
                    if (GetExitCodeProcess(hProc, &exitCode) &&
                        exitCode != STILL_ACTIVE) {
                        CloseHandle(hProc);
                        *pp = p->next;
                        free_process(p);
                        InterlockedDecrement64(&g_proc_count);
                        cleaned++;
                        continue;
                    }
                    CloseHandle(hProc);
                } else {
                    /* Can't open = likely dead */
                    *pp = p->next;
                    free_process(p);
                    InterlockedDecrement64(&g_proc_count);
                    cleaned++;
                    continue;
                }
                pp = &(*pp)->next;
            }
        }
        LeaveCriticalSection(&g_proc_lock);

        if (cleaned > 0 && g_verbose) {
            fprintf(stderr, "orphan cleanup raised: %d\n", cleaned);
        }
    }
    return 0;
}

/* ── Stop all traces ───────────────────────────────────────────────── */
static void stop_all_traces(void) {
    stop_named_session(KERNEL_SESSION);
    stop_named_session(USER_SESSION);

    if (g_kernel_trace_handle != INVALID_PROCESSTRACE_HANDLE) {
        CloseTrace(g_kernel_trace_handle);
        g_kernel_trace_handle = INVALID_PROCESSTRACE_HANDLE;
    }
    if (g_user_trace_handle != INVALID_PROCESSTRACE_HANDLE) {
        CloseTrace(g_user_trace_handle);
        g_user_trace_handle = INVALID_PROCESSTRACE_HANDLE;
    }
}

/* ── Shutdown summary: sorted findings table ─────────────────────── */
typedef struct {
    ULONG pid;
    WCHAR image[260];
    USHORT tags;
    int level;
} finding_entry_t;

static int finding_cmp_desc(const void *a, const void *b) {
    const finding_entry_t *fa = (const finding_entry_t *)a;
    const finding_entry_t *fb = (const finding_entry_t *)b;
    if (fb->level != fa->level) return fb->level - fa->level;
    return (int)fa->pid - (int)fb->pid;
}

static void print_shutdown_summary(void) {
    /* Collect all processes with level >= LOW */
    int capacity = 256, count = 0;
    finding_entry_t *findings = (finding_entry_t *)malloc(
        capacity * sizeof(finding_entry_t));
    if (!findings) return;

    EnterCriticalSection(&g_proc_lock);
    for (int i = 0; i < PROC_HASH_SIZE; i++) {
        process_record_t *p = g_proc_table[i];
        while (p) {
            int lvl = compute_level(p->tags);
            if (lvl >= LEVEL_LOW) {
                if (count >= capacity) {
                    capacity *= 2;
                    findings = (finding_entry_t *)realloc(
                        findings, capacity * sizeof(finding_entry_t));
                    if (!findings) { LeaveCriticalSection(&g_proc_lock); return; }
                }
                findings[count].pid = p->pid;
                wcsncpy(findings[count].image, p->image, 259);
                findings[count].tags = p->tags;
                findings[count].level = lvl;
                count++;
            }
            p = p->next;
        }
    }
    LeaveCriticalSection(&g_proc_lock);

    if (count == 0) {
        printf("\n  No findings at LOW or above.\n\n");
        free(findings);
        return;
    }

    qsort(findings, count, sizeof(finding_entry_t), finding_cmp_desc);

    /* Print header */
    printf("\n");
    set_console_color(COLOR_BANNER);
    printf("==================================================================\n");
    printf("  KASSANDRA - FINDINGS SUMMARY  (%d processes flagged)\n", count);
    printf("==================================================================\n");
    set_console_color(g_default_attr);

    printf("  %-10s %-8s %-30s %s\n", "LEVEL", "PID", "IMAGE", "TAGS");
    printf("  ---------- -------- ------------------------------ "
           "-----------------------------\n");

    for (int i = 0; i < count; i++) {
        char tag_buf[512];
        build_tag_string(findings[i].tags, tag_buf, sizeof(tag_buf));

        char img[260];
        WideCharToMultiByte(CP_OEMCP, 0, findings[i].image, -1,
                            img, sizeof(img), NULL, NULL);

        set_console_color(level_color(findings[i].level));
        printf("  %-10s %-8u %-30s %s\n",
               level_name(findings[i].level),
               findings[i].pid, img, tag_buf);
    }
    set_console_color(g_default_attr);

    printf("  ---------- -------- ------------------------------ "
           "-----------------------------\n");

    /* Also write summary to log file */
    if (g_log_file) {
        fprintf(g_log_file,
                "\n==================== FINDINGS SUMMARY "
                "====================\n");
        fprintf(g_log_file, "  %-10s %-8s %-30s %s\n",
                "LEVEL", "PID", "IMAGE", "TAGS");
        for (int i = 0; i < count; i++) {
            char tag_buf[512];
            build_tag_string(findings[i].tags, tag_buf, sizeof(tag_buf));
            char img[260];
            WideCharToMultiByte(CP_OEMCP, 0, findings[i].image, -1,
                                img, sizeof(img), NULL, NULL);
            fprintf(g_log_file, "  %-10s %-8u %-30s %s\n",
                    level_name(findings[i].level),
                    findings[i].pid, img, tag_buf);
        }
        fprintf(g_log_file, "================================================="
                "=========\n");
    }

    char log_narrow[MAX_PATH];
    WideCharToMultiByte(CP_OEMCP, 0, g_log_path, -1,
                        log_narrow, sizeof(log_narrow), NULL, NULL);

    set_console_color(COLOR_BANNER);
    printf("\n  Findings logged to: %s\n\n", log_narrow);
    set_console_color(g_default_attr);

    free(findings);
}

/* ── Usage / help ──────────────────────────────────────────────────── */
static void print_usage(void) {
    printf("kassandra - Windows ETW threat detector\n\n");
    printf("Usage: kassandra.exe [options]\n\n");
    printf("Options:\n");
    printf("  -v, --verbose     Show in-place banner with telemetry counters.\n");
    printf("  -o, --output FILE Write LOW+ findings to FILE "
           "(default: kassandra_findings.log)\n");
    printf("  -h, --help        Print this help text.\n\n");
    printf("Requires elevation (SeSystemProfilePrivilege).\n");
}

/* ── Main ──────────────────────────────────────────────────────────── */
int wmain(int argc, WCHAR *argv[]) {
    int show_help = 0;
    int log_specified = 0;

    for (int i = 1; i < argc; i++) {
        if (wcscmp(argv[i], L"-h") == 0 || wcscmp(argv[i], L"--help") == 0)
            show_help = 1;
        else if (wcscmp(argv[i], L"-v") == 0 ||
                 wcscmp(argv[i], L"--verbose") == 0)
            g_verbose = 1;
        else if ((wcscmp(argv[i], L"-o") == 0 ||
                  wcscmp(argv[i], L"--output") == 0) && i + 1 < argc) {
            wcsncpy(g_log_path, argv[++i], MAX_PATH - 1);
            log_specified = 1;
        }
    }

    if (show_help) { print_usage(); return 0; }

    /* Console setup */
    g_console = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (GetConsoleScreenBufferInfo(g_console, &csbi))
        g_default_attr = csbi.wAttributes;
    else
        g_default_attr = COLOR_DEFAULT;

    /* Enable ANSI escape processing */
    DWORD consoleMode = 0;
    GetConsoleMode(g_console, &consoleMode);
    SetConsoleMode(g_console, consoleMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);

    /* Open findings log file */
    g_log_file = _wfopen(g_log_path, L"a");
    if (g_log_file) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        fprintf(g_log_file,
                "\n--- kassandra session started %04d-%02d-%02d %02d:%02d:%02d ---\n",
                st.wYear, st.wMonth, st.wDay,
                st.wHour, st.wMinute, st.wSecond);
        fflush(g_log_file);
        char log_narrow[MAX_PATH];
        WideCharToMultiByte(CP_OEMCP, 0, g_log_path, -1,
                            log_narrow, sizeof(log_narrow), NULL, NULL);
        fprintf(stderr, "[info] findings log: %s\n", log_narrow);
    } else {
        fprintf(stderr, "Warning: could not open log file, "
                "continuing without file output\n");
    }

    /* Init sync */
    InitializeCriticalSection(&g_proc_lock);
    InitializeCriticalSection(&g_output_lock);
    memset(g_proc_table, 0, sizeof(g_proc_table));

    /* Init FNV-1a hash sets for sleep/proxy API detection */
    init_api_hash_sets();

    /* Resolve exports from ntdll, kernel32, kernelbase */
    memset(&g_ntdll_exports, 0, sizeof(g_ntdll_exports));
    memset(&g_kernel32_exports, 0, sizeof(g_kernel32_exports));
    memset(&g_kernelbase_exports, 0, sizeof(g_kernelbase_exports));
    resolve_module_exports(&g_ntdll_exports, "ntdll.dll");
    resolve_module_exports(&g_kernel32_exports, "kernel32.dll");
    resolve_module_exports(&g_kernelbase_exports, "kernelbase.dll");

    if (g_verbose) {
        fprintf(stderr, "Resolved exports: ntdll=%d kernel32=%d kernelbase=%d\n",
                g_ntdll_exports.count, g_kernel32_exports.count,
                g_kernelbase_exports.count);
    }

    /* Ctrl-C handler */
    SetConsoleCtrlHandler(ctrl_handler, TRUE);

    /* Timing */
    QueryPerformanceFrequency(&g_perf_freq);
    QueryPerformanceCounter(&g_start_time);

    /* Suppress detections until rundown completes */
    InterlockedExchange(&g_rundown_active, 1);

    /* Start kernel trace */
    if (start_kernel_trace() != 0) {
        DeleteCriticalSection(&g_proc_lock);
        DeleteCriticalSection(&g_output_lock);
        return 1;
    }

    /* Launch kernel trace pump thread */
    HANDLE hKernelPump = CreateThread(NULL, 0, trace_pump,
                                      &g_kernel_trace_handle, 0, NULL);

    /* Start user trace (non-fatal if it fails) */
    HANDLE hUserPump = NULL;
    if (start_user_trace() == 0) {
        hUserPump = CreateThread(NULL, 0, trace_pump,
                                 &g_user_trace_handle, 0, NULL);
    }

    /* Run rundown to capture existing processes */
    run_rundown();

    fprintf(stderr, "[info] user trace pump live\n");
    fprintf(stderr, "[info] kernel trace pump live\n");

    /* Start orphan cleanup thread */
    HANDLE hOrphan = CreateThread(NULL, 0, orphan_cleanup_thread, NULL, 0, NULL);

    fprintf(stderr, "[info] consumer running - Ctrl-C to stop\n");

    /* Verbose: set up scroll region for banner */
    if (g_verbose) {
        printf("\x1b[2J"); /* clear screen */
        printf("\x1b[9;1r"); /* set scroll region: lines 9+ */
        printf("\x1b[9;1H"); /* move cursor to line 9 */
    }

    /* Main loop */
    while (g_running) {
        if (g_verbose) print_banner();
        Sleep(g_verbose ? 1000 : 100);
    }

    /* Shutdown */
    fprintf(stderr, "\nstop requested\n");
    stop_all_traces();

    if (hKernelPump) { WaitForSingleObject(hKernelPump, 5000); CloseHandle(hKernelPump); }
    if (hUserPump)   { WaitForSingleObject(hUserPump, 5000);   CloseHandle(hUserPump);   }
    if (hOrphan)     { WaitForSingleObject(hOrphan, 1000);     CloseHandle(hOrphan);     }

    /* Reset scroll region */
    if (g_verbose) printf("\x1b[r");

    /* Print findings summary sorted by severity */
    print_shutdown_summary();

    /* Close log file */
    if (g_log_file) {
        fclose(g_log_file);
        g_log_file = NULL;
    }

    /* Cleanup process table */
    EnterCriticalSection(&g_proc_lock);
    for (int i = 0; i < PROC_HASH_SIZE; i++) {
        process_record_t *p = g_proc_table[i];
        while (p) {
            process_record_t *next = p->next;
            free_process(p);
            p = next;
        }
        g_proc_table[i] = NULL;
    }
    LeaveCriticalSection(&g_proc_lock);

    /* Cleanup exports */
    free(g_ntdll_exports.entries);
    free(g_kernel32_exports.entries);
    free(g_kernelbase_exports.entries);

    DeleteCriticalSection(&g_proc_lock);
    DeleteCriticalSection(&g_output_lock);

    fprintf(stderr, "consumer stopped\n");
    return 0;
}
