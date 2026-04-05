/*
 * adapter_hook.dll - IAT hook injected into RvControlSvc.exe
 *
 * Hooks GetAdaptersAddresses in the service's import table to rename
 * radminvpn0 → "Famatech Radmin VPN Ethernet Adapter".
 *
 * Loaded by placing in C:\radmin\ and adding to the service's import
 * table via a thin shim, OR by using the CRT init trick below:
 * We export a function that shelper.dll or another Radmin DLL can call.
 *
 * Simplest injection: rename this to a DLL the service already loads
 * from its directory. We'll use "amt.dll" which is in the extracted files.
 *
 * Build:
 *   i686-w64-mingw32-gcc -shared -o adapter_hook.dll adapter_hook.c \
 *       -liphlpapi -lws2_32 -Wl,--enable-stdcall-fixup
 */

#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <tlhelp32.h>
#include <string.h>

#define TAP_DESC L"radminvpn0"
#define RADMIN_DESC L"Famatech Radmin VPN Ethernet Adapter"
#define RADMIN_FRIENDLY L"Radmin VPN"
#define RADMIN_GUID "{B06D84D1-AF78-41EC-A5B9-3CCE67652882}"

static ULONG (WINAPI *real_GetAdaptersAddresses)(
    ULONG, ULONG, PVOID, PIP_ADAPTER_ADDRESSES, PULONG) = NULL;

static void dbg(const char *msg);  /* forward decl */

static ULONG WINAPI hook_GetAdaptersAddresses(
    ULONG Family, ULONG Flags, PVOID Rsvd,
    PIP_ADAPTER_ADDRESSES Addrs, PULONG Size)
{
    ULONG ret;
    PIP_ADAPTER_ADDRESSES cur;

    dbg("hook_GetAdaptersAddresses: CALLED");
    if (!real_GetAdaptersAddresses) return ERROR_NOT_SUPPORTED;
    ret = real_GetAdaptersAddresses(Family, Flags, Rsvd, Addrs, Size);

    if (ret == ERROR_SUCCESS && Addrs) {
        for (cur = Addrs; cur; cur = cur->Next) {
            char buf[256];
            if (cur->Description) {
                WideCharToMultiByte(CP_UTF8, 0, cur->Description, -1, buf, sizeof(buf), NULL, NULL);
                char msg[512];
                wsprintfA(msg, "hook: adapter desc='%s'", buf);
                dbg(msg);
            }
            if (cur->Description && wcscmp(cur->Description, TAP_DESC) == 0) {
                /* Description buffer may be too small for our longer string.
                 * Allocate new buffers using HeapAlloc (survives the call). */
                WCHAR *newDesc = (WCHAR*)HeapAlloc(GetProcessHeap(), 0, 128);
                WCHAR *newFN = (WCHAR*)HeapAlloc(GetProcessHeap(), 0, 64);
                if (newDesc) { wcscpy(newDesc, RADMIN_DESC); cur->Description = newDesc; }
                if (newFN) { wcscpy(newFN, RADMIN_FRIENDLY); cur->FriendlyName = newFN; }
                {
                    char guid_msg[256];
                    wsprintfA(guid_msg, "hook: RENAMED radminvpn0 -> Famatech Radmin VPN Ethernet Adapter (keeping GUID: %s)", cur->AdapterName);
                    dbg(guid_msg);
                }
            }
        }
    }
    return ret;
}

static void log_evt_raw(const char *buf);  /* forward decl */
static volatile DWORD g_pump_parent;       /* forward decl — used for counter logging */

/* ====== CreateThread hook — log thread start addresses ====== */

static unsigned char *tramp_ct = NULL;

typedef HANDLE (WINAPI *CreateThreadFn)(LPSECURITY_ATTRIBUTES, SIZE_T,
    LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);

static int ct_count = 0;

static HANDLE WINAPI hook_CreateThread_fn(LPSECURITY_ATTRIBUTES sa, SIZE_T stack,
    LPTHREAD_START_ROUTINE start, LPVOID param, DWORD flags, LPDWORD tid)
{
    ct_count++;
    /* Log first 10 and every 500th */
    if (ct_count <= 10 || (ct_count % 500) == 0) {
        char buf[256];
        /* If start=004AD532 (CRT wrapper), real func is at *param */
        if ((DWORD)(DWORD_PTR)start == 0x004AD532 && param != NULL) {
            /* CRT wrapper: param[0]=thread_func, param[1]=real_this */
            DWORD thread_func = *((DWORD*)param);
            DWORD real_this = *((DWORD*)param + 1);
            DWORD work_func = 0, work_arg = 0;
            char modname[64] = "?";
            if (real_this != 0 && thread_func == 0x004935F0) {
                /* Executor pattern: real_this+0x30 = work function */
                work_func = *((DWORD*)((char*)(DWORD_PTR)real_this + 0x30));
                work_arg = *((DWORD*)((char*)(DWORD_PTR)real_this + 0x34));
                HMODULE mod = NULL;
                if (work_func) {
                    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                                      (LPCSTR)(DWORD_PTR)work_func, &mod);
                    if (mod) GetModuleFileNameA(mod, modname, sizeof(modname));
                }
            }
            wsprintfA(buf, "CreateThread #%d tfunc=%p this=%p work=%p mod=%s",
                      ct_count, (void*)(DWORD_PTR)thread_func,
                      (void*)(DWORD_PTR)real_this,
                      (void*)(DWORD_PTR)work_func, modname);
        } else {
            wsprintfA(buf, "CreateThread #%d start=%p param=%p flags=%lx",
                      ct_count, (void*)start, param, flags);
        }
        log_evt_raw(buf);
    }
    return ((CreateThreadFn)tramp_ct)(sa, stack, start, param, flags, tid);
}

/* ====== IPv6 socket block — force IPv4 fallback ====== */

static SOCKET (WINAPI *real_WSASocketW)(int af, int type, int protocol,
    LPWSAPROTOCOL_INFOW info, GROUP g, DWORD flags) = NULL;

static SOCKET WINAPI hook_WSASocketW(int af, int type, int protocol,
    LPWSAPROTOCOL_INFOW info, GROUP g, DWORD flags)
{
    if (af == AF_INET6) {
        char buf[128];
        SOCKET s = real_WSASocketW(af, type, protocol, info, g, flags);
        wsprintfA(buf, "WSASocketW: AF_INET6 type=%d proto=%d → socket=%p", type, protocol, (void*)(intptr_t)s);
        log_evt_raw(buf);
        return s;  /* let it through, just log */
    }
    return real_WSASocketW(af, type, protocol, info, g, flags);
}

/* ====== RegSetKeySecurity hook — prevent DACL lock on Wine ====== */
/*
 * Root cause (proven 2026-04-04):
 *   Radmin calls RegSetKeySecurity on the Registration subkey with a DACL
 *   that only allows SYSTEM (S-1-5-18). On Windows the service IS SYSTEM
 *   so it can re-open the key. Wine SCM doesn't give the service the SYSTEM
 *   SID → all subsequent RegOpenKeyExW calls get ACCESS_DENIED.
 *
 * Fix: no-op RegSetKeySecurity. The key stays with the default permissive
 * DACL, which is fine since we're the only user of this Wine prefix.
 */

static LONG (WINAPI *real_RegSetKeySecurity)(HKEY hKey, SECURITY_INFORMATION si,
    PSECURITY_DESCRIPTOR psd) = NULL;

static LONG WINAPI hook_RegSetKeySecurity(HKEY hKey, SECURITY_INFORMATION si,
    PSECURITY_DESCRIPTOR psd)
{
    (void)hKey; (void)si; (void)psd;
    log_evt_raw("RegSetKeySecurity: BLOCKED (Wine SYSTEM SID workaround)");
    return ERROR_SUCCESS;  /* pretend it worked */
}

/* Patch IAT of a specific module */
static void patch_iat(HMODULE mod)
{
    PIMAGE_DOS_HEADER dos;
    PIMAGE_NT_HEADERS nt;
    PIMAGE_IMPORT_DESCRIPTOR imp;
    DWORD rva, old;

    if (!mod) return;
    dos = (PIMAGE_DOS_HEADER)mod;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    nt = (PIMAGE_NT_HEADERS)((BYTE*)mod + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;
    rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (!rva) return;

    imp = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)mod + rva);
    for (; imp->Name; imp++) {
        char *dll = (char*)mod + imp->Name;

        PIMAGE_THUNK_DATA orig = (PIMAGE_THUNK_DATA)((BYTE*)mod + imp->OriginalFirstThunk);
        PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((BYTE*)mod + imp->FirstThunk);

        if (_stricmp(dll, "IPHLPAPI.DLL") == 0 || _stricmp(dll, "iphlpapi.dll") == 0) {
            for (; orig->u1.AddressOfData; orig++, thunk++) {
                if (orig->u1.Ordinal & IMAGE_ORDINAL_FLAG) continue;
                PIMAGE_IMPORT_BY_NAME by_name =
                    (PIMAGE_IMPORT_BY_NAME)((BYTE*)mod + orig->u1.AddressOfData);
                if (strcmp(by_name->Name, "GetAdaptersAddresses") == 0) {
                    real_GetAdaptersAddresses = (void*)thunk->u1.Function;
                    VirtualProtect(&thunk->u1.Function, sizeof(DWORD_PTR), PAGE_READWRITE, &old);
                    thunk->u1.Function = (DWORD_PTR)hook_GetAdaptersAddresses;
                    VirtualProtect(&thunk->u1.Function, sizeof(DWORD_PTR), old, &old);
                    dbg("hooked GetAdaptersAddresses");
                }
            }
        }

        if (_stricmp(dll, "WS2_32.DLL") == 0 || _stricmp(dll, "ws2_32.dll") == 0 ||
            _stricmp(dll, "WS2_32.dll") == 0) {
            orig = (PIMAGE_THUNK_DATA)((BYTE*)mod + imp->OriginalFirstThunk);
            thunk = (PIMAGE_THUNK_DATA)((BYTE*)mod + imp->FirstThunk);
            for (; orig->u1.AddressOfData; orig++, thunk++) {
                if (orig->u1.Ordinal & IMAGE_ORDINAL_FLAG) continue;
                PIMAGE_IMPORT_BY_NAME by_name =
                    (PIMAGE_IMPORT_BY_NAME)((BYTE*)mod + orig->u1.AddressOfData);
                if (strcmp(by_name->Name, "WSASocketW") == 0) {
                    real_WSASocketW = (void*)thunk->u1.Function;
                    VirtualProtect(&thunk->u1.Function, sizeof(DWORD_PTR), PAGE_READWRITE, &old);
                    thunk->u1.Function = (DWORD_PTR)hook_WSASocketW;
                    VirtualProtect(&thunk->u1.Function, sizeof(DWORD_PTR), old, &old);
                    dbg("hooked WSASocketW");
                }
            }
        }

        if (_stricmp(dll, "ADVAPI32.dll") == 0 || _stricmp(dll, "advapi32.dll") == 0 ||
            _stricmp(dll, "ADVAPI32.DLL") == 0) {
            orig = (PIMAGE_THUNK_DATA)((BYTE*)mod + imp->OriginalFirstThunk);
            thunk = (PIMAGE_THUNK_DATA)((BYTE*)mod + imp->FirstThunk);
            for (; orig->u1.AddressOfData; orig++, thunk++) {
                if (orig->u1.Ordinal & IMAGE_ORDINAL_FLAG) continue;
                PIMAGE_IMPORT_BY_NAME by_name =
                    (PIMAGE_IMPORT_BY_NAME)((BYTE*)mod + orig->u1.AddressOfData);
                if (strcmp(by_name->Name, "RegSetKeySecurity") == 0) {
                    real_RegSetKeySecurity = (void*)thunk->u1.Function;
                    VirtualProtect(&thunk->u1.Function, sizeof(DWORD_PTR), PAGE_READWRITE, &old);
                    thunk->u1.Function = (DWORD_PTR)hook_RegSetKeySecurity;
                    VirtualProtect(&thunk->u1.Function, sizeof(DWORD_PTR), old, &old);
                    dbg("hooked RegSetKeySecurity (Wine SYSTEM SID workaround)");
                }
            }
        }
    }
}

/* Exported dummy function so the DLL stays loaded */
__declspec(dllexport) int AdapterHookInit(void) { return 1; }

static void dbg(const char *msg)
{
    HANDLE f = CreateFileA("C:\\radmin_hook_debug.log",
        FILE_APPEND_DATA, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL,
        OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f != INVALID_HANDLE_VALUE) {
        DWORD w;
        WriteFile(f, msg, strlen(msg), &w, NULL);
        WriteFile(f, "\r\n", 2, &w, NULL);
        CloseHandle(f);
    }
}

/* ====== Event + State Machine logging hooks ====== */

/*
 * We inline-hook two functions in RvControlSvc.exe:
 *   FUN_00444b50 = event dispatcher (switch on param_1[4] = event type)
 *   FUN_0044bfe0 = state machine transition (new_state, expected_current)
 *
 * Both are __thiscall: ECX=this, params on stack.
 * Image base is 0x00400000 (standard PE32 EXE).
 */

/* Trampoline buffers — executable memory allocated at init */
static unsigned char *tramp_evt = NULL;   /* trampoline for event dispatcher */
static unsigned char *tramp_fsm = NULL;   /* trampoline for state machine */
static unsigned char *tramp_conn = NULL;  /* trampoline for FUN_0043c020 (connect) */
static unsigned char *tramp_notify = NULL; /* trampoline for FUN_0044b080 (notify ROL) */
static unsigned char *tramp_listen_vpn = NULL; /* trampoline for ROLClient_ListenVpn */
static unsigned char *tramp_set_vaddr = NULL;  /* trampoline for ROLClient_SetVirtualAddresses */
static unsigned char *tramp_frame_send = NULL; /* trampoline for FUN_0041c0c0 (frame send) */

/* ====== Frame send hook (FUN_0041c0c0) ======
 *
 * FUN_0041c0c0 is __thiscall: ECX=this, stack: param_1(buf), param_2(len), param_3
 * Called for each ReadFile completion from the driver.
 * param_1 points to the ReadFile buffer, param_2 is the byte count.
 * The buffer starts with 2 reserved bytes, then TLV: [u32 mac][u32 framelen][frame...]
 * We check if the TLV contains an ICMP frame and log call count + result.
 */
static volatile LONG g_frame_send_count = 0;
static volatile LONG g_frame_send_icmp = 0;
static volatile LONG g_frame_send_ok = 0;
static volatile LONG g_frame_send_fail = 0;

/* Check if TLV buffer (after +2 skip that the service does) contains ICMP */
static int tlv_has_icmp(const unsigned char *buf, unsigned int len)
{
    /* buf points to start of buffer, but service passes (buf+2, len) to filter.
     * Here we receive the raw params: buf = buffer base, len includes the +2.
     * The TLV data starts at buf+2. */
    const unsigned char *p = buf + 2;
    unsigned int remain = (len > 2) ? len - 2 : 0;
    while (remain >= 8) {
        /* [u32 mac_prefix][u32 frame_len] */
        unsigned int flen = *(unsigned int *)(p + 4);
        if (flen == 0 || flen > 1600 || 8 + flen > remain) break;
        const unsigned char *frame = p + 8;
        /* Check ethertype=0x0800 and IP proto=1 (ICMP) */
        if (flen >= 34 && frame[12] == 0x08 && frame[13] == 0x00 && frame[23] == 1)
            return 1;
        p += 8 + flen;
        remain -= 8 + flen;
    }
    return 0;
}

typedef unsigned int (__attribute__((thiscall)) *frame_send_fn)(void *this_ptr,
    int param_1, unsigned int param_2, unsigned int param_3);

static unsigned int __attribute__((thiscall)) hook_frame_send(void *this_ptr,
    int param_1, unsigned int param_2, unsigned int param_3)
{
    LONG n = InterlockedIncrement(&g_frame_send_count);
    int is_icmp = 0;

    if (param_1 && param_2 > 10)
        is_icmp = tlv_has_icmp((const unsigned char *)param_1, param_2);

    if (is_icmp)
        InterlockedIncrement(&g_frame_send_icmp);

    /* Call real function */
    unsigned int ret = ((frame_send_fn)tramp_frame_send)(this_ptr, param_1, param_2, param_3);

    if (ret & 0xFF)
        InterlockedIncrement(&g_frame_send_ok);
    else
        InterlockedIncrement(&g_frame_send_fail);

    /* Log every ICMP call, and periodic summary for non-ICMP */
    if (is_icmp) {
        char buf[128];
        wsprintfA(buf, "SEND #%ld ICMP len=%u ret=%u (ok=%ld fail=%ld total=%ld)",
                  n, param_2, ret & 0xFF, g_frame_send_ok, g_frame_send_fail, n);
        dbg(buf);
    } else if ((n % 200) == 0) {
        char buf[128];
        wsprintfA(buf, "SEND summary #%ld: icmp=%ld ok=%ld fail=%ld",
                  n, g_frame_send_icmp, g_frame_send_ok, g_frame_send_fail);
        dbg(buf);
    }

    return ret;
}

/* Log event type to a separate file for easy parsing */
static HANDLE evt_log_handle = INVALID_HANDLE_VALUE;
static int evt_2b_count = 0;

/* Forward declarations for cross-referenced functions */
static unsigned char *make_trampoline(void *original, int len);
static int write_jmp(void *src, void *dst, int patch_len);
static void install_rol_hooks(void);
static void dump_rol_counts(void);

static void log_evt_raw(const char *buf)
{
    if (evt_log_handle == INVALID_HANDLE_VALUE) {
        evt_log_handle = CreateFileA("C:\\radmin_events.log",
            FILE_APPEND_DATA, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL,
            OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    }
    if (evt_log_handle != INVALID_HANDLE_VALUE) {
        DWORD w;
        WriteFile(evt_log_handle, buf, strlen(buf), &w, NULL);
        WriteFile(evt_log_handle, "\r\n", 2, &w, NULL);
    }
}

static void log_event(int event_type, int sub_type)
{
    char buf[256];
    /* Throttle event 0x2b: only log first 5 and then every 1000th */
    if (event_type == 0x2b) {
        evt_2b_count++;
        if (evt_2b_count > 5 && (evt_2b_count % 1000) != 0)
            return;
        wsprintfA(buf, "EVT 0x%x sub=%d (count=%d)", event_type, sub_type, evt_2b_count);
    } else {
        evt_2b_count = 0;
        wsprintfA(buf, "EVT %d (0x%x) sub=%d", event_type, event_type, sub_type);
    }
    log_evt_raw(buf);
}

/* Log state transitions */
static int fsm_noop_count = 0;

static void log_state(int new_state, int expected_current, int actual_current)
{
    /* Throttle no-op transitions (same state) */
    if (new_state == actual_current && new_state == expected_current) {
        fsm_noop_count++;
        if (fsm_noop_count > 3 && (fsm_noop_count % 1000) != 0)
            return;
    } else {
        fsm_noop_count = 0;
    }
    char buf[128];
    wsprintfA(buf, "FSM cur=%d exp=%d new=%d", actual_current, expected_current, new_state);
    log_evt_raw(buf);
}

/* Hook typedefs using thiscall convention (ECX=this, args on stack) */
typedef unsigned int (__attribute__((thiscall)) *EventDispatchFn)(void *self, void *param_1);
typedef unsigned int (__attribute__((thiscall)) *StateMachineFn)(void *self, int new_st, int exp_st);
typedef unsigned char (__attribute__((thiscall)) *ConnectFn)(void *self, unsigned int p1, unsigned int p2, unsigned int p3, unsigned int p4, unsigned int p5);
typedef unsigned int (__attribute__((thiscall)) *NotifyROLFn)(void *self);

/*
 * Hook for FUN_00444b50 (event dispatcher)
 * Event type = param_1[4] = *(int*)((char*)param_1 + 0x10)
 * Log-only — no forwarding or injection.
 */
static unsigned int __attribute__((thiscall))
hook_event_dispatch(void *self, void *param_1)
{
    if (param_1) {
        int event_type = *(int *)((char *)param_1 + 0x10);
        int sub_type = *(int *)((char *)param_1 + 0x30);
        log_event(event_type, sub_type);
    }
    return ((EventDispatchFn)tramp_evt)(self, param_1);
}

/*
 * Hook for FUN_0044bfe0 (state machine)
 * Current state = *(int*)((char*)self + 0x5318)
 */
static unsigned int __attribute__((thiscall))
hook_state_machine(void *self, int new_state, int expected)
{
    int actual = *(int *)((char *)self + 0x5318);
    log_state(new_state, expected, actual);

    /* When transitioning TO state 3 (connecting), dump the task manager fields
       that FUN_0045e450 checks before creating the CListener task. */
    if (new_state == 3 && actual != 3) {
        DWORD task_mgr = *(DWORD *)((int)self + 0x5110);
        char buf[512];
        if (task_mgr > 0x10000) {
            DWORD f6c = *(DWORD *)(task_mgr + 0x6c);
            DWORD f70 = *(DWORD *)(task_mgr + 0x70);
            DWORD f168 = *(DWORD *)(task_mgr + 0x168);
            /* Also dump the dispatch table at self+0x5100 */
            DWORD conn_this = *(DWORD *)((int)self + 0x5100);
            DWORD f510c = *(DWORD *)((int)self + 0x510c);
            DWORD f5108 = *(DWORD *)((int)self + 0x5108);
            wsprintfA(buf, "FSM3_PROBE: task_mgr=%p +6c=%p +70=%p +168=%p "
                      "conn=%p 510c=%p 5108=%p",
                      (void*)task_mgr, (void*)f6c, (void*)f70, (void*)f168,
                      (void*)conn_this, (void*)f510c, (void*)f5108);
            log_evt_raw(buf);
            /* If +6c or +70 is NULL, that's the blocker! */
            if (!f6c || !f70) {
                log_evt_raw("FSM3_PROBE: *** +6c or +70 is NULL — CListener will NOT be created ***");
            }
        } else {
            wsprintfA(buf, "FSM3_PROBE: task_mgr=%p (INVALID)", (void*)task_mgr);
            log_evt_raw(buf);
        }
    }

    return ((StateMachineFn)tramp_fsm)(self, new_state, expected);
}

/*
 * Hook for FUN_0044b080 (notify ROL of state change via vtable[0x84])
 * __fastcall with ECX=this. Reads this->0x5100 (sub-object), then
 * calls (*(*(sub+8))+0x84)(state). We log the vtable chain to find
 * what function is actually at slot 33.
 */
static int notify_logged = 0;

static unsigned int __attribute__((thiscall))
hook_notify_rol(void *self)
{
    DWORD rolObj = *(DWORD *)((char *)self + 0x5100);
    int state = *(int *)((char *)self + 0x5318);

    /* Retry ROL hooks if not installed yet */
    if (!tramp_listen_vpn) install_rol_hooks();

    /* Dump ROL call counts on shutdown or after state 3 */
    if (notify_logged >= 2) dump_rol_counts();

    if (rolObj && notify_logged < 20) {
        notify_logged++;

        /* Read ROL DLL globals to check readiness */
        HMODULE rolDll = GetModuleHandleA("RvROLClient.dll");
        DWORD shutdownFlag = 0xDEAD, singleton = 0xDEAD;
        if (rolDll) {
            /* DAT_10154294 (connector singleton): DLL base + 0x154294
               DAT_101542bc (shutdown flag):       DLL base + 0x1542bc */
            DWORD *pSingleton = (DWORD *)((char *)rolDll + 0x154294);
            DWORD *pShutdown  = (DWORD *)((char *)rolDll + 0x1542bc);
            singleton = *pSingleton;
            shutdownFlag = *pShutdown;
        }

        char buf[512];
        wsprintfA(buf, "NOTIFY_ROL #%d: state=%d rolDll=%p "
                  "shutdown_flag=0x%x singleton=%p",
                  notify_logged, state,
                  (void*)rolDll,
                  shutdownFlag,
                  (void*)(DWORD_PTR)singleton);
        log_evt_raw(buf);
    }
    return ((NotifyROLFn)tramp_notify)(self);
}

/* ====== ROL export call counting via INT3 breakpoints + VEH ====== */
/* Patch first byte of each ROL export to INT3 (0xCC). A Vectored Exception
   Handler catches EXCEPTION_BREAKPOINT, logs the hit, restores the byte,
   sets EFLAGS.TF (single-step), and continues. On the subsequent
   EXCEPTION_SINGLE_STEP, re-patches INT3. One byte = zero boundary issues. */

#define ROL_MAX_BP 64

struct rol_bp {
    const char *name;
    unsigned char *addr;
    unsigned char orig_byte;
    volatile LONG count;
    int active;
};

static struct rol_bp rol_bps[ROL_MAX_BP];
static int rol_bp_count = 0;
static CRITICAL_SECTION rol_bp_cs;
static int rol_bp_cs_init = 0;

/* === Deferred registry writer === */
static volatile int g_regwrite_pending = 0;
static BYTE g_regwrite_buf[4096];
static volatile DWORD g_regwrite_size = 0;
static HKEY g_reg_hk = NULL;  /* pre-opened in DllMain where HKLM access works */

static LONG WINAPI rol_veh(EXCEPTION_POINTERS *ep)
{
    DWORD code = ep->ExceptionRecord->ExceptionCode;
    DWORD eip = (DWORD)ep->ExceptionRecord->ExceptionAddress;

    if (code == EXCEPTION_BREAKPOINT) {
        /* Check if it's one of our breakpoints */
        for (int i = 0; i < rol_bp_count; i++) {
            if (rol_bps[i].active && (DWORD)(DWORD_PTR)rol_bps[i].addr == eip) {
                InterlockedIncrement(&rol_bps[i].count);

                /* Special: dump connector fields when ConnWork fires */
                if (rol_bps[i].name[0] == 'I' && rol_bps[i].name[4] == 'C' &&
                    rol_bps[i].name[5] == 'o' && rol_bps[i].name[6] == 'n' &&
                    rol_bps[i].name[7] == 'n' && rol_bps[i].name[8] == 'W') {
                    /* FUN_10075580 is __fastcall, param_1 in ECX */
                    DWORD p1 = ep->ContextRecord->Ecx;
                    if (p1 > 0x10000) {
                        char buf[512];
                        DWORD f74  = *(DWORD*)(p1 + 0x74);
                        DWORD f78  = *(DWORD*)(p1 + 0x78);
                        DWORD f7c  = *(DWORD*)(p1 + 0x7c);
                        DWORD f88  = *(DWORD*)(p1 + 0x88);
                        DWORD f8c  = *(DWORD*)(p1 + 0x8c);
                        DWORD f90  = *(DWORD*)(p1 + 0x90);
                        DWORD f94  = *(DWORD*)(p1 + 0x94);
                        DWORD f134 = *(DWORD*)(p1 + 0x134);
                        DWORD f3e8 = *(DWORD*)(p1 + 0x3e8);
                        DWORD f1a4 = *(DWORD*)(p1 + 0x1a4);
                        /* Also check FUN_10003bd0 result: reads *(*(p+0x74)+8) */
                        DWORD connState = 0;
                        if (f74 > 0x10000) connState = *(DWORD*)(f74 + 8);
                        wsprintfA(buf, "CONNWORK_DUMP: p1=%p +74=%p(st=%d) +78=%d +7c=%d "
                                  "+88=%p +8c=%p +90=%p +94=%p +134=%p +3E8=%p +1A4=%d",
                                  (void*)p1, (void*)f74, connState, f78, f7c,
                                  (void*)f88, (void*)f8c, (void*)f90,
                                  (void*)f94, (void*)f134, (void*)f3e8, f1a4);
                        log_evt_raw(buf);

                    }
                }

                /* Special: dump ConnWork fields */
                if (rol_bps[i].name[0] == 'I' && rol_bps[i].name[4] == 'C' &&
                    rol_bps[i].name[5] == 'o' && rol_bps[i].name[6] == 'n' &&
                    rol_bps[i].name[7] == 'n' && rol_bps[i].name[8] == 'W') {
                    DWORD p1 = ep->ContextRecord->Ecx;
                    if (p1 > 0x10000) {
                        char buf[256];
                        wsprintfA(buf, "CONNWORK: session=%p gate@+50=%d",
                                  (void*)p1, *(BYTE*)(p1 + 0x50));
                        log_evt_raw(buf);
                    }
                }

                /* Gate check (FUN_100a4cc0) — log only, no forced return */
                if (rol_bps[i].name[4] == 'G' && rol_bps[i].name[5] == 'a' &&
                    rol_bps[i].name[6] == 't' && rol_bps[i].name[7] == 'e') {
                    DWORD ecx = ep->ContextRecord->Ecx;
                    BYTE real_val = 0;
                    if (ecx > 0x10000) real_val = *(BYTE*)(ecx + 0x50);
                    static int gate_log_count = 0;
                    if (gate_log_count < 20) {
                        gate_log_count++;
                        char buf[256];
                        wsprintfA(buf, "GATE_CHECK: param=%p val=%d",
                                  (void*)ecx, real_val);
                        log_evt_raw(buf);
                    }
                }

                /* Special: dump CWorker vtable[2] blocker fields */
                if (rol_bps[i].name[4] == 'W' && rol_bps[i].name[5] == 'o' &&
                    rol_bps[i].name[6] == 'r' && rol_bps[i].name[7] == 'k') {
                    /* FUN_100a4b60 is __fastcall, ECX = param_1 (= session + 0x18) */
                    DWORD p = ep->ContextRecord->Ecx;
                    if (p > 0x10000) {
                        char buf[512];
                        DWORD handler = *(DWORD*)(p - 0xc);  /* *(param_1-0xc) handler ptr */
                        DWORD done_flag = *(DWORD*)(p + 0x38); /* *(param_1+0x38) done flag */
                        DWORD id_hi = *(DWORD*)(p + 0x8);
                        DWORD id_lo = *(DWORD*)(p + 0xc);
                        DWORD handler_vtable = 0;
                        DWORD inner = 0;
                        if (handler > 0x10000) {
                            inner = *(DWORD*)handler;
                            if (inner > 0x10000) handler_vtable = *(DWORD*)(inner + 8);
                        }
                        /* Find which module handler_vt2 belongs to */
                        HMODULE hMod = NULL;
                        char modname[128] = "???";
                        if (handler_vtable > 0x10000) {
                            GetModuleHandleExA(
                                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                (LPCSTR)(DWORD_PTR)handler_vtable, &hMod);
                            if (hMod) GetModuleFileNameA(hMod, modname, sizeof(modname));
                        }
                        /* Also dump first 6 DWORDs of handler object */
                        DWORD h0=0,h1=0,h2=0,h3=0,h4=0,h5=0;
                        if (handler > 0x10000) {
                            h0=*(DWORD*)(handler);
                            h1=*(DWORD*)(handler+4);
                            h2=*(DWORD*)(handler+8);
                            h3=*(DWORD*)(handler+12);
                            h4=*(DWORD*)(handler+16);
                            h5=*(DWORD*)(handler+20);
                        }
                        /* Also check the event handle at param_1+0x44+4 = ecx+0x48 */
                        DWORD evt_struct = 0, evt_handle = 0;
                        if (p > 0x10000) {
                            evt_struct = *(DWORD*)(p + 0x44);  /* event struct ptr or inline */
                            evt_handle = *(DWORD*)(p + 0x48);  /* *(param+0x44+4) = event handle */
                        }
                        /* Check the enqueue gate flag at session+0x50 */
                        /* p = ecx = session+0x18, so session = p - 0x18 */
                        DWORD session_base = p - 0x18;
                        BYTE gate_flag = 0;
                        if (session_base > 0x10000) gate_flag = *(BYTE*)(session_base + 0x50);
                        wsprintfA(buf, "WORKER_DO: ecx=%p handler=%p done=%d "
                                  "id=%08x:%08x gate@+50=%d evt@+48=%p [%s]",
                                  (void*)p, (void*)handler, done_flag,
                                  id_hi, id_lo, gate_flag,
                                  (void*)evt_handle, modname);
                        log_evt_raw(buf);
                        wsprintfA(buf, "WORKER_DO_OBJ: handler[0..5]=%08x %08x %08x %08x %08x %08x",
                                  h0, h1, h2, h3, h4, h5);
                        log_evt_raw(buf);
                    }
                }

                /* Special: dump CrtSBody handler args */
                if (rol_bps[i].name[4] == 'C' && rol_bps[i].name[5] == 'r' &&
                    rol_bps[i].name[6] == 't') {
                    /* __thiscall: ECX=this, stack: param_1,param_2,param_3 */
                    DWORD ecx = ep->ContextRecord->Ecx;
                    DWORD esp = ep->ContextRecord->Esp;
                    /* stack: [esp]=retaddr [esp+4]=param_1 [esp+8]=param_2 [esp+c]=param_3 */
                    DWORD p1=0,p2=0,p3=0;
                    if (esp > 0x10000) { p1=*(DWORD*)(esp+4); p2=*(DWORD*)(esp+8); p3=*(DWORD*)(esp+12); }
                    /* Check FUN_10002310 equivalent: this+0x7c field */
                    DWORD shutdown_check = 0;
                    if (ecx > 0x10000) shutdown_check = *(DWORD*)(ecx + 0x7c);
                    char buf[256];
                    wsprintfA(buf, "CRTS_BODY: this=%p +7c(shutdown?)=%08x p1=%p p2=%08x p3=%08x",
                              (void*)ecx, shutdown_check, (void*)p1, p2, p3);
                    log_evt_raw(buf);
                }

                /* Special: dump EnqTarget (FUN_100a8950) — the critical enqueue path */
                if (rol_bps[i].name[4] == 'E' && rol_bps[i].name[5] == 'n' &&
                    rol_bps[i].name[6] == 'q' && rol_bps[i].name[7] == 'T') {
                    /* __thiscall: ECX=this (parent obj), stack: ref_lo, ref_hi, message, flags */
                    DWORD ecx = ep->ContextRecord->Ecx;
                    DWORD esp = ep->ContextRecord->Esp;
                    DWORD ref_lo=0, ref_hi=0, msg_ptr=0, flags=0;
                    if (esp > 0x10000) {
                        ref_lo  = *(DWORD*)(esp+4);
                        ref_hi  = *(DWORD*)(esp+8);
                        msg_ptr = *(DWORD*)(esp+12);
                        flags   = *(DWORD*)(esp+16);
                    }
                    DWORD evt_type = 0;
                    if (msg_ptr > 0x10000) evt_type = *(DWORD*)(msg_ptr + 0x10);
                    /* Check shutdown flag at this+0x08+0x48 = this+0x50 */
                    DWORD shutdown = 0;
                    if (ecx > 0x10000) shutdown = *(DWORD*)(ecx + 0x50);
                    char buf[512];
                    static int enq_log_count = 0;
                    if (enq_log_count < 50) {
                        enq_log_count++;
                        wsprintfA(buf, "ENQ_TARGET: this=%p ref=%08x:%08x msg=%p evt=0x%x flags=%d shutdown=%d",
                                  (void*)ecx, ref_lo, ref_hi, (void*)msg_ptr, evt_type, flags, shutdown);
                        log_evt_raw(buf);
                        /* If ref is 0:0, this is THE BUG — silent drop */
                        if (ref_lo == 0 && ref_hi == 0) {
                            log_evt_raw("ENQ_TARGET: *** REF IS 0:0 — MESSAGE WILL BE SILENTLY DROPPED ***");
                        }
                        /* Save parent address for counter logging */
                        if (!g_pump_parent && ecx > 0x10000) {
                            g_pump_parent = ecx;
                        }
                    }
                }

                /* Special: dump Signal (FUN_100a0dc0) — SetEvent after enqueue */
                if (rol_bps[i].name[4] == 'S' && rol_bps[i].name[5] == 'i' &&
                    rol_bps[i].name[6] == 'g' && rol_bps[i].name[7] == 'n') {
                    DWORD ecx = ep->ContextRecord->Ecx;
                    DWORD handle = 0;
                    if (ecx > 0x10000) handle = *(DWORD*)(ecx + 0x4);
                    char buf[256];
                    static int sig_log_count = 0;
                    if (sig_log_count < 20) {
                        sig_log_count++;
                        wsprintfA(buf, "SIGNAL: evt_obj=%p handle=%p (NULL=no signal!)",
                                  (void*)ecx, (void*)handle);
                        log_evt_raw(buf);
                    }
                    /* Node dump removed — was causing use-after-free crashes
                       on recycled queue nodes (stale pointers → page fault) */
                }

                /* Special: dump Forwarding callback (FUN_100304c0) */
                if (rol_bps[i].name[4] == 'F' && rol_bps[i].name[5] == 'w' &&
                    rol_bps[i].name[6] == 'd') {
                    DWORD ecx = ep->ContextRecord->Ecx;
                    DWORD esp = ep->ContextRecord->Esp;
                    DWORD node = 0;
                    if (esp > 0x10000) node = *(DWORD*)(esp+4);
                    DWORD msg_ref = 0, ref_lo = 0, ref_hi = 0;
                    if (node > 0x10000) {
                        msg_ref = *(DWORD*)(node + 0x8);
                        ref_lo = *(DWORD*)(node + 0x10);
                        ref_hi = *(DWORD*)(node + 0x14);
                    }
                    char buf[256];
                    wsprintfA(buf, "FWD_CALLBACK: ecx=%p node=%p msg=%p ref=%08x:%08x",
                              (void*)ecx, (void*)node, (void*)msg_ref, ref_lo, ref_hi);
                    log_evt_raw(buf);
                }

                /* Special: dump WorkerRun (FUN_10027cc0) */
                if (rol_bps[i].name[4] == 'W' && rol_bps[i].name[5] == 'o' &&
                    rol_bps[i].name[6] == 'r' && rol_bps[i].name[7] == 'k' &&
                    rol_bps[i].name[8] == 'e' && rol_bps[i].name[9] == 'r' &&
                    rol_bps[i].name[10] == 'R') {
                    DWORD ecx = ep->ContextRecord->Ecx;
                    char buf[256];
                    wsprintfA(buf, "WORKER_RUN: ecx=%p", (void*)ecx);
                    log_evt_raw(buf);
                }

                /* Special: dump QueuePush (FUN_100a8050) */
                if (rol_bps[i].name[4] == 'Q' && rol_bps[i].name[5] == 'u' &&
                    rol_bps[i].name[6] == 'e' && rol_bps[i].name[7] == 'u') {
                    DWORD ecx = ep->ContextRecord->Ecx;
                    DWORD esp = ep->ContextRecord->Esp;
                    DWORD msg_obj = 0;
                    if (esp > 0x10000) msg_obj = *(DWORD*)(esp+4);
                    /* Check queue counter at this+0x3c and shutdown at this+0x48 */
                    DWORD counter = 0, shutdown = 0;
                    if (ecx > 0x10000) {
                        counter = *(DWORD*)(ecx + 0x3c);
                        shutdown = *(DWORD*)(ecx + 0x48);
                    }
                    char buf[256];
                    static int qp_log_count = 0;
                    if (qp_log_count < 20) {
                        qp_log_count++;
                        wsprintfA(buf, "QUEUE_PUSH: this=%p msg=%p counter=%d shutdown=%d",
                                  (void*)ecx, (void*)msg_obj, counter, shutdown);
                        log_evt_raw(buf);
                    }
                }

                /* Special: dump HashInsert args */
                if (rol_bps[i].name[4] == 'H' && rol_bps[i].name[5] == 'a' &&
                    rol_bps[i].name[6] == 's') {
                    /* __thiscall: ECX=this(hashtable), stack: param_1(id_hi),param_2(id_lo),param_3,param_4,param_5 */
                    DWORD ecx = ep->ContextRecord->Ecx;
                    DWORD esp = ep->ContextRecord->Esp;
                    DWORD p1=0,p2=0,p3=0,p4=0,p5=0;
                    if (esp > 0x10000) {
                        p1=*(DWORD*)(esp+4); p2=*(DWORD*)(esp+8); p3=*(DWORD*)(esp+12);
                        p4=*(DWORD*)(esp+16); p5=*(DWORD*)(esp+20);
                    }
                    char buf[256];
                    wsprintfA(buf, "HASH_INSERT: table=%p id=%08x:%08x obj=%p out4=%p out5=%p",
                              (void*)ecx, p1, p2, (void*)p3, (void*)p4, (void*)p5);
                    log_evt_raw(buf);
                }

                /* === Task system probes === */

                /* SVC_TskSched (0x0045eda0): task scheduler entry */
                if (rol_bps[i].name[0] == 'S' && rol_bps[i].name[4] == 'T' &&
                    rol_bps[i].name[7] == 'S' && rol_bps[i].name[8] == 'c') {
                    static int sched_log = 0;
                    if (sched_log < 10) {
                        sched_log++;
                        DWORD ecx = ep->ContextRecord->Ecx;
                        DWORD esp = ep->ContextRecord->Esp;
                        DWORD param1 = 0;
                        if (esp > 0x10000) param1 = *(DWORD*)(esp+4);
                        char buf[512];
                        wsprintfA(buf, "TSK_SCHED: ecx(task_mgr)=%p CListener=%p vtable=%p +34=%08x +138=%p",
                                  (void*)ecx, (void*)param1,
                                  param1 > 0x10000 ? (void*)*(DWORD*)param1 : 0,
                                  param1 > 0x10000 ? *(DWORD*)(param1+0x34) : 0,
                                  param1 > 0x10000 ? (void*)*(DWORD*)(param1+0x138) : 0);
                        log_evt_raw(buf);
                    }
                }

                /* SVC_TskCh2 (0x00452bb0): sched_chain_2 entry */
                if (rol_bps[i].name[0] == 'S' && rol_bps[i].name[4] == 'T' &&
                    rol_bps[i].name[7] == 'C' && rol_bps[i].name[8] == 'h') {
                    static int ch2_log = 0;
                    if (ch2_log < 5) {
                        ch2_log++;
                        DWORD ecx = ep->ContextRecord->Ecx;
                        char buf[256];
                        DWORD f14 = (ecx > 0x10000) ? *(DWORD*)(ecx+0x14) : 0;
                        wsprintfA(buf, "TSK_CH2: node=%p +14=%p %s",
                                  (void*)ecx, (void*)f14,
                                  f14 == 0 ? "*** +14 NULL ***" : "OK");
                        log_evt_raw(buf);
                    }
                }

                /* SVC_TskGuard (0x004638b0): guard check */
                if (rol_bps[i].name[0] == 'S' && rol_bps[i].name[4] == 'T' &&
                    rol_bps[i].name[7] == 'G' && rol_bps[i].name[8] == 'u') {
                    static int guard_log = 0;
                    if (guard_log < 5) {
                        guard_log++;
                        DWORD ecx = ep->ContextRecord->Ecx;
                        char buf[256];
                        wsprintfA(buf, "TSK_GUARD: ecx=%p +10=%p +14=%p",
                                  (void*)ecx,
                                  ecx > 0x10000 ? (void*)*(DWORD*)(ecx+0x10) : 0,
                                  ecx > 0x10000 ? (void*)*(DWORD*)(ecx+0x14) : 0);
                        log_evt_raw(buf);
                    }
                }

                /* SVC_TskVt2 (0x004606c0): CListener vtable[2] — timing/schedule
                   This function is void but the caller (TSK_EXEC) checks EAX.
                   We let it run normally and just log — the real bug is upstream. */
                if (rol_bps[i].name[0] == 'S' && rol_bps[i].name[4] == 'T' &&
                    rol_bps[i].name[7] == 'V' && rol_bps[i].name[8] == 't') {
                    static int vt2_log = 0;
                    if (vt2_log < 5) {
                        vt2_log++;
                        DWORD ecx = ep->ContextRecord->Ecx;
                        char buf[256];
                        wsprintfA(buf, "TSK_VT2: ecx=%p (let run, tracing residual EAX)", (void*)ecx);
                        log_evt_raw(buf);
                    }
                }

                /* SVC_TskExec (0x00464200): CListener vtable6[1] — main execution */
                if (rol_bps[i].name[0] == 'S' && rol_bps[i].name[4] == 'T' &&
                    rol_bps[i].name[7] == 'E' && rol_bps[i].name[8] == 'x') {
                    static int exec_log = 0;
                    if (exec_log < 10) {
                        exec_log++;
                        DWORD ecx = ep->ContextRecord->Ecx;
                        char buf[512];
                        if (ecx > 0x10000) {
                            wsprintfA(buf, "TSK_EXEC: ecx=%p +b4=%p +b8=%p +ec=%p +e8=%d -14=%08x -48_vt=%p",
                                      (void*)ecx,
                                      (void*)*(DWORD*)(ecx+0xb4), (void*)*(DWORD*)(ecx+0xb8),
                                      (void*)*(DWORD*)(ecx+0xec), *(BYTE*)(ecx+0xe8),
                                      *(DWORD*)(ecx-0x14),
                                      (void*)*(DWORD*)(ecx-0x48));
                            log_evt_raw(buf);
                        }
                    }
                }

                /* SVC_TskLoop (0x00462590): CListener vtable6[4] — connect loop */
                if (rol_bps[i].name[0] == 'S' && rol_bps[i].name[4] == 'T' &&
                    rol_bps[i].name[7] == 'L' && rol_bps[i].name[8] == 'o') {
                    DWORD ecx = ep->ContextRecord->Ecx;
                    char buf[256];
                    wsprintfA(buf, "TSK_LOOP: ecx=%p (vtable6[4] connect loop!)", (void*)ecx);
                    log_evt_raw(buf);
                }

                /* SVC_TskDisp (0x0046a2d0): dispatch from vtable[2] */
                if (rol_bps[i].name[0] == 'S' && rol_bps[i].name[4] == 'T' &&
                    rol_bps[i].name[7] == 'D' && rol_bps[i].name[8] == 'i') {
                    DWORD esp = ep->ContextRecord->Esp;
                    DWORD param1 = 0, param2 = 0, param3 = 0;
                    if (esp > 0x10000) {
                        param1 = *(DWORD*)(esp+4);
                        param2 = *(DWORD*)(esp+8);
                        param3 = *(DWORD*)(esp+12);
                    }
                    char buf[256];
                    static int disp_log = 0;
                    if (disp_log < 10) {
                        disp_log++;
                        wsprintfA(buf, "TSK_DISP: param1=%p param2=%08x param3=%08x",
                                  (void*)param1, param2, param3);
                        log_evt_raw(buf);
                    }
                }

                /* SVC_TskWork (0x00427860) */
                if (rol_bps[i].name[0] == 'S' && rol_bps[i].name[4] == 'T' &&
                    rol_bps[i].name[7] == 'W' && rol_bps[i].name[8] == 'o') {
                    static int work_log = 0;
                    if (work_log < 3) {
                        work_log++;
                        char buf[128];
                        wsprintfA(buf, "TSK_WORK: hit");
                        log_evt_raw(buf);
                    }
                }

                /* SVC_TskConn (0x00414150) */
                if (rol_bps[i].name[0] == 'S' && rol_bps[i].name[4] == 'T' &&
                    rol_bps[i].name[7] == 'C' && rol_bps[i].name[8] == 'o' &&
                    rol_bps[i].name[9] == 'n' && rol_bps[i].name[10] == 'n') {
                    char buf[128];
                    wsprintfA(buf, "TSK_CONN: hit");
                    log_evt_raw(buf);
                }

                /* SVC_RdyChk (0x00469490): readiness check
                   param_1 via stack, ECX=timer obj */
                if (rol_bps[i].name[0] == 'S' && rol_bps[i].name[4] == 'R' &&
                    rol_bps[i].name[7] == 'C' && rol_bps[i].name[8] == 'h') {
                    DWORD esp = ep->ContextRecord->Esp;
                    DWORD p1 = (esp > 0x10000) ? *(DWORD*)(esp+4) : 0;
                    static int rdy_log = 0;
                    if (rdy_log < 10) {
                        rdy_log++;
                        char buf[128];
                        wsprintfA(buf, "RDY_CHK: param1=%d (4=CListener) ecx=%p",
                                  p1, (void*)ep->ContextRecord->Ecx);
                        log_evt_raw(buf);
                    }
                }

                /* SVC_RdyD14 (0x0046d140): CListener-specific check 1 */
                if (rol_bps[i].name[0] == 'S' && rol_bps[i].name[4] == 'R' &&
                    rol_bps[i].name[7] == 'D' && rol_bps[i].name[8] == '1' &&
                    rol_bps[i].name[9] == '4') {
                    DWORD esp = ep->ContextRecord->Esp;
                    DWORD p1 = (esp > 0x10000) ? *(DWORD*)(esp+4) : 0;
                    char buf[128];
                    wsprintfA(buf, "RDY_D140: param1=%p (CListener check 1)", (void*)p1);
                    log_evt_raw(buf);
                }

                /* SVC_RdyD11 (0x0046d110): CListener-specific check 2 */
                if (rol_bps[i].name[0] == 'S' && rol_bps[i].name[4] == 'R' &&
                    rol_bps[i].name[7] == 'D' && rol_bps[i].name[8] == '1' &&
                    rol_bps[i].name[9] == '1') {
                    DWORD esp = ep->ContextRecord->Esp;
                    DWORD p1 = (esp > 0x10000) ? *(DWORD*)(esp+4) : 0;
                    char buf[128];
                    wsprintfA(buf, "RDY_D110: param1=%p (CListener check 2)", (void*)p1);
                    log_evt_raw(buf);
                }

                /* SVC_VT2Ret (0x004644bc): TEST EAX,EAX right after vtable[2] call */
                if (rol_bps[i].name[0] == 'S' && rol_bps[i].name[4] == 'V' &&
                    rol_bps[i].name[7] == 'R' && rol_bps[i].name[8] == 'e') {
                    DWORD eax = ep->ContextRecord->Eax;
                    static int vt2ret_log = 0;
                    if (vt2ret_log < 5) {
                        vt2ret_log++;
                        char buf[128];
                        wsprintfA(buf, "VT2_RET: EAX=%08x (%s)",
                                  eax, eax ? "NON-ZERO" : "ZERO → skip");
                        log_evt_raw(buf);
                    }
                }

                /* SVC_Chk01..14: common checks in FUN_00469490 */
                if (rol_bps[i].name[0] == 'S' && rol_bps[i].name[4] == 'C' &&
                    rol_bps[i].name[5] == 'h' && rol_bps[i].name[6] == 'k') {
                    static int chk_log = 0;
                    if (chk_log < 50) {
                        chk_log++;
                        char buf[128];
                        wsprintfA(buf, "CHK: %s fired", rol_bps[i].name);
                        log_evt_raw(buf);
                    }
                }

                /* SVC_RegPrs (0x00432e80): parse registration response */
                if (rol_bps[i].name[0] == 'S' && rol_bps[i].name[4] == 'R' &&
                    rol_bps[i].name[5] == 'e' && rol_bps[i].name[6] == 'g' &&
                    rol_bps[i].name[7] == 'P') {
                    DWORD esp = ep->ContextRecord->Esp;
                    DWORD ecx = ep->ContextRecord->Ecx;
                    DWORD p1 = (esp > 0x10000) ? *(DWORD*)(esp+4) : 0;
                    char buf[256];
                    wsprintfA(buf, "REG_PARSE: ecx=%p param1=%p (registration response parser)",
                              (void*)ecx, (void*)p1);
                    log_evt_raw(buf);
                    if (p1 > 0x10000) {
                        wsprintfA(buf, "REG_PARSE: data[0..3]=%08x %08x %08x %08x",
                                  *(DWORD*)p1, *(DWORD*)(p1+4),
                                  *(DWORD*)(p1+8), *(DWORD*)(p1+12));
                        log_evt_raw(buf);
                    }
                }

                /* SVC_RegWrt (0x0046c6b0): WRITE ServerPassword
                   VEH context can't do registry calls (Wine lock reentrance).
                   Capture data and let a helper thread write it. */
                if (rol_bps[i].name[0] == 'S' && rol_bps[i].name[4] == 'R' &&
                    rol_bps[i].name[5] == 'e' && rol_bps[i].name[6] == 'g' &&
                    rol_bps[i].name[7] == 'W') {
                    DWORD esp = ep->ContextRecord->Esp;
                    DWORD p1 = (esp > 0x10000) ? *(DWORD*)(esp+4) : 0;
                    char buf[512];
                    wsprintfA(buf, "REG_WRITE_SERVERPWD: param1=%p", (void*)p1);
                    log_evt_raw(buf);
                    if (p1 > 0x10000) {
                        DWORD data_ptr = *(DWORD*)p1;
                        DWORD data_size = *(DWORD*)(p1 + 4);
                        wsprintfA(buf, "REG_WRITE_DATA: ptr=%p size=%d [%08x %08x %08x %08x]",
                                  (void*)data_ptr, data_size,
                                  *(DWORD*)(p1), *(DWORD*)(p1+4),
                                  *(DWORD*)(p1+8), *(DWORD*)(p1+12));
                        log_evt_raw(buf);
                        /* Copy data for deferred write */
                        if (data_ptr > 0x10000 && data_size > 0 && data_size < 4096 &&
                            !g_regwrite_pending) {
                            memcpy(g_regwrite_buf, (void*)data_ptr, data_size);
                            g_regwrite_size = data_size;
                            g_regwrite_pending = 1;
                            log_evt_raw("REG_WRITE: queued for deferred write");
                        }
                    }
                }

                /* === Readiness check forcing DISABLED (2026-04-04) ===
                 * Root cause was RegSetKeySecurity DACL lock, now fixed by
                 * hooking RegSetKeySecurity → no-op. Checks should pass naturally.
                 * Keeping breakpoints active for logging only. */
                if ((rol_bps[i].name[0] == 'S' && rol_bps[i].name[4] == 'C' &&
                     rol_bps[i].name[5] == 'h' && rol_bps[i].name[6] == 'k' &&
                     rol_bps[i].name[7] == '0' && rol_bps[i].name[8] == '7') ||
                    (rol_bps[i].name[0] == 'S' && rol_bps[i].name[4] == 'R' &&
                     rol_bps[i].name[5] == 'd' && rol_bps[i].name[6] == 'y' &&
                     rol_bps[i].name[7] == 'D')) {
                    DWORD esp = ep->ContextRecord->Esp;
                    DWORD param1 = (esp > 0x10000) ? *(DWORD*)(esp+4) : 0;
                    DWORD param2 = (esp > 0x10000) ? *(DWORD*)(esp+8) : 0;
                    static int chk7_log = 0;
                    if (chk7_log < 30) {
                        chk7_log++;
                        char buf[128];
                        wsprintfA(buf, "CHK_NOFRC: %s param1=%d param2=%p (letting execute naturally)",
                                  rol_bps[i].name, param1, (void*)param2);
                        log_evt_raw(buf);
                    }
                    /* Let it execute normally — don't force return */
                }

                /* === Payload NULL investigation probes (2026-04-04) === */

                /* INT_IDisp (FUN_1001ec20): ROL internal event dispatcher
                   __stdcall+thiscall: ECX=this, [ESP+4]=param_1 (event)
                   param_1[4] = *(param_1+0x10) = internal event type
                   param_1->0x3c = response data ptr (NULL = the bug) */
                if (rol_bps[i].name[4] == 'I' && rol_bps[i].name[5] == 'D') {
                    DWORD ecx = ep->ContextRecord->Ecx;
                    DWORD esp = ep->ContextRecord->Esp;
                    DWORD param1 = (esp > 0x10000) ? *(DWORD*)(esp+4) : 0;
                    DWORD evt_type = 0, field_3c = 0;
                    if (param1 > 0x10000) {
                        evt_type = *(DWORD*)(param1 + 0x10);
                        field_3c = *(DWORD*)(param1 + 0x3c);
                    }
                    char buf[256];
                    static int idisp_log = 0;
                    if (idisp_log < 50) {
                        idisp_log++;
                        wsprintfA(buf, "IDISP: this=%p evt=%p itype=0x%x +3c=%p",
                                  (void*)ecx, (void*)param1, evt_type, (void*)field_3c);
                        log_evt_raw(buf);
                        /* For type 2 (registration response), dump more fields */
                        if (evt_type == 2 && param1 > 0x10000) {
                            DWORD f30 = *(DWORD*)(param1 + 0x30);
                            DWORD f34 = *(DWORD*)(param1 + 0x34);
                            DWORD f38 = *(DWORD*)(param1 + 0x38);
                            wsprintfA(buf, "IDISP_TYPE2: +30=%08x +34=%08x +38=%p +3c=%p <<< RESPONSE PTR",
                                      f30, f34, (void*)f38, (void*)field_3c);
                            log_evt_raw(buf);
                        }
                    }
                }

                /* INT_IResp (FUN_1001e340): registration response handler
                   __thiscall: ECX=this, [ESP+4]=param_1 (internal event)
                   KEY CHECK: param_1->0x3c — if NULL → payload lost */
                if (rol_bps[i].name[4] == 'I' && rol_bps[i].name[5] == 'R') {
                    DWORD ecx = ep->ContextRecord->Ecx;
                    DWORD esp = ep->ContextRecord->Esp;
                    DWORD param1 = (esp > 0x10000) ? *(DWORD*)(esp+4) : 0;
                    DWORD field_3c = 0, field_38 = 0, field_10 = 0;
                    if (param1 > 0x10000) {
                        field_3c = *(DWORD*)(param1 + 0x3c);
                        field_38 = *(DWORD*)(param1 + 0x38);
                        field_10 = *(DWORD*)(param1 + 0x10);
                    }
                    char buf[256];
                    wsprintfA(buf, "IRESP: this=%p evt=%p itype=0x%x +38=%p +3c=%p%s",
                              (void*)ecx, (void*)param1, field_10,
                              (void*)field_38, (void*)field_3c,
                              field_3c == 0 ? " <<< NULL PAYLOAD!" : " (has data)");
                    log_evt_raw(buf);
                    /* If +3c is non-NULL, dump what's at +3c+0x30 (the actual payload) */
                    if (field_3c > 0x10000) {
                        DWORD payload = *(DWORD*)(field_3c + 0x30);
                        wsprintfA(buf, "IRESP_PAYLOAD: *(+3c+0x30)=%p (this becomes event +0x38)",
                                  (void*)payload);
                        log_evt_raw(buf);
                    }
                }

                /* INT_IProd (evt2a_unnamed @ 10014c90): event 0x2a producer
                   __thiscall: ECX=this (no stack args)
                   Reads DAT_101541a0 (ROL_base+0x1541a0) for event +0x38 */
                if (rol_bps[i].name[4] == 'I' && rol_bps[i].name[5] == 'P') {
                    DWORD ecx = ep->ContextRecord->Ecx;
                    HMODULE rolDll = GetModuleHandleA("RvROLClient.dll");
                    DWORD global_val = 0;
                    if (rolDll) global_val = *(DWORD*)((DWORD)rolDll + 0x1541a0);
                    DWORD sub_field = 0, field_21 = 0;
                    if (ecx > 0x10000) {
                        sub_field = *(DWORD*)(ecx + 0xb0);
                        field_21 = *(DWORD*)(ecx + 0x84);
                    }
                    char buf[256];
                    wsprintfA(buf, "IPROD: this=%p DAT_1541a0=%p(payload) +b0=%d(sub) +84=%d%s",
                              (void*)ecx, (void*)global_val, sub_field, field_21,
                              global_val == 0 ? " <<< WILL PRODUCE NULL PAYLOAD!" : "");
                    log_evt_raw(buf);
                }

                /* Restore original byte */
                DWORD old;
                VirtualProtect(rol_bps[i].addr, 1, PAGE_EXECUTE_READWRITE, &old);
                *rol_bps[i].addr = rol_bps[i].orig_byte;
                VirtualProtect(rol_bps[i].addr, 1, old, &old);
                FlushInstructionCache(GetCurrentProcess(), rol_bps[i].addr, 1);

                /* Set single-step to re-enable BP after one instruction */
                ep->ContextRecord->EFlags |= 0x100; /* TF */

                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }
    }
    else if (code == EXCEPTION_SINGLE_STEP) {
        /* Check if this is a HARDWARE WATCHPOINT hit (DR6 bit 0) */
        if (ep->ContextRecord->Dr6 & 0x1) {
            DWORD eip_val = ep->ContextRecord->Eip;
            DWORD ecx_val = ep->ContextRecord->Ecx;
            DWORD counter_val = 0;
            if (g_pump_parent) counter_val = *(DWORD*)(g_pump_parent + 0x44);
            /* Find which module EIP is in */
            HMODULE hMod = NULL;
            char modname[128] = "???";
            GetModuleHandleExA(
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                (LPCSTR)(DWORD_PTR)eip_val, &hMod);
            if (hMod) GetModuleFileNameA(hMod, modname, sizeof(modname));
            DWORD rva = hMod ? (eip_val - (DWORD)hMod) : 0;

            char buf[512];
            static int hw_hit_count = 0;
            if (hw_hit_count < 20) {
                hw_hit_count++;
                wsprintfA(buf, "HW_WATCH: eip=%p (RVA=%08x) ecx=%p counter=%d mod=%s",
                          (void*)eip_val, rva, (void*)ecx_val, counter_val, modname);
                log_evt_raw(buf);
            }

            /* Clear DR6 to acknowledge */
            ep->ContextRecord->Dr6 = 0;
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        /* Re-enable all breakpoints that were temporarily removed */
        for (int i = 0; i < rol_bp_count; i++) {
            if (rol_bps[i].active && *rol_bps[i].addr == rol_bps[i].orig_byte) {
                DWORD old;
                VirtualProtect(rol_bps[i].addr, 1, PAGE_EXECUTE_READWRITE, &old);
                *rol_bps[i].addr = 0xCC;
                VirtualProtect(rol_bps[i].addr, 1, old, &old);
                FlushInstructionCache(GetCurrentProcess(), rol_bps[i].addr, 1);
            }
        }
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

static struct { const char *name; DWORD rva; } rol_export_table[] = {
    /* Exports */
    {"Connect",            0x23f30},
    {"ContinueConnect",    0x24010},
    {"EnumPublicNetworks", 0x241a0},
    {"InitConnector",      0x246a0},
    {"InitDll",            0x24760},
    {"InitSRP",            0x247d0},
    {"Listen",             0x249c0},
    {"ListenVpn",          0x24aa0},
    {"ManageLicense",      0x24ba0},
    {"ManageNetwork",      0x24c80},
    {"Register",           0x24e20},
    {"SetCompression",     0x25230},
    {"SetVirtualAddresses",0x25470},
    {"ShutdownConnector",  0x255f0},
    /* Internal functions */
    {"INT_ConnWork",       0x75580},  /* FUN_10075580 — connector main work */
    {"INT_Evt2bProd",      0x74c50},  /* FUN_10074c50 — event 0x2b producer */
    {"INT_Evt29Prod",      0x20460},  /* FUN_10020460 — event 0x29 producer */
    {"INT_ConnInit",       0x4030},   /* FUN_10004030 — called in InitConnector */
    {"INT_StartConn",      0x2ac00},  /* FUN_1002ac00 — register connector */
    {"INT_EvtWaitFB",      0x43720},  /* FUN_10043720 — event wait fallback */
    {"INT_WorkerDo",       0xa4b60},  /* FUN_100a4b60 — CWorker vtable[2], returns 0 = blocker */
    {"INT_CrtSBody",       0xa8cb0},  /* FUN_100a8cb0 — crypto handler vtable[2] */
    {"INT_HashInsert",     0xa8210},  /* FUN_100a8210 — hash table insert, returns 0 = fail */
    {"INT_EvtCheck",       0xa0cf0},  /* FUN_100a0cf0 — event check after done=1, only reached if handler returns 1 */
    {"INT_GateCheck",      0xa4cc0},  /* FUN_100a4cc0 — gate check, log only */
    {"INT_EnqTarget",      0xa8950},  /* FUN_100a8950 — parent vtable[4], enqueue target */
    {"INT_Signal",         0xa0dc0},  /* FUN_100a0dc0 — SetEvent signal after enqueue */
    {"INT_QueuePush",      0xa8050},  /* FUN_100a8050 — actual linked list push */
    {"INT_Fwd",            0x304c0},  /* FUN_100304c0 — forwarding callback (local→global) */
    {"INT_WorkerRun",      0x27cc0},  /* FUN_10027cc0 — worker thread creation? */
    {"INT_NodeDtor",       0x29ff0},  /* FUN_10029ff0 — queue node destructor (vtable[0]) */
    {"INT_QueueLoop",      0xa40c0},  /* FUN_100a40c0 — WaitForMultipleObjects processing loop */
    {"INT_QueueProc",      0xa4010},  /* FUN_100a4010 — process element in loop */
    /* Payload NULL investigation (2026-04-04) */
    {"INT_IDisp",          0xec20},   /* FUN_1001ec20 — ROL internal event dispatcher (switch on type) */
    {"INT_IResp",          0x1e340},  /* FUN_1001e340 — registration response handler (checks +0x3c) */
    {"INT_IProd",          0x14c90},  /* evt2a_unnamed — event 0x2a producer (reads DAT_101541a0) */
    {NULL, 0}
};

/* Check if the running EXE is v1.4 (file size 1179712). Breakpoints use
 * hardcoded addresses from the v1.4 binary — installing them on a different
 * version would write INT3 at random code locations and crash. */
static int is_v14_exe(void)
{
    char path[MAX_PATH];
    if (!GetModuleFileNameA(NULL, path, MAX_PATH)) return 0;
    HANDLE f = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) return 0;
    DWORD size = GetFileSize(f, NULL);
    CloseHandle(f);
    return (size == 1179712);  /* v1.4 RvControlSvc.exe */
}

static void install_rol_hooks(void)
{
    HMODULE rolDll = GetModuleHandleA("RvROLClient.dll");
    if (!rolDll) {
        dbg("ROL hooks: RvROLClient.dll not loaded yet");
        return;
    }

    /* All breakpoints (ROL RVAs + SVC absolute addrs) are v1.4-specific.
     * Skip them on other versions to avoid corrupting code. */
    if (!is_v14_exe()) {
        dbg("ROL hooks: not v1.4 exe, skipping all INT3 breakpoints");
        tramp_listen_vpn = (unsigned char *)1; /* sentinel: installed */
        return;
    }

    /* Install VEH (first handler) */
    AddVectoredExceptionHandler(1, rol_veh);

    char buf[256];
    wsprintfA(buf, "ROL DLL base: %p", rolDll);
    dbg(buf);

    for (int i = 0; rol_export_table[i].name && rol_bp_count < ROL_MAX_BP; i++) {
        unsigned char *fn = (unsigned char *)rolDll + rol_export_table[i].rva;
        int idx = rol_bp_count++;

        rol_bps[idx].name = rol_export_table[i].name;
        rol_bps[idx].addr = fn;
        rol_bps[idx].orig_byte = *fn;
        rol_bps[idx].count = 0;
        rol_bps[idx].active = 1;

        DWORD old;
        VirtualProtect(fn, 1, PAGE_EXECUTE_READWRITE, &old);
        *fn = 0xCC;
        VirtualProtect(fn, 1, old, &old);
        FlushInstructionCache(GetCurrentProcess(), fn, 1);
    }

    wsprintfA(buf, "ROL breakpoints: %d set", rol_bp_count);
    dbg(buf);

    /* Service-side breakpoints (absolute addresses, not ROL-relative) */
    static struct { const char *name; DWORD addr; } svc_bps[] = {
        {"SVC_ConnectDisp",  0x0043c020},  /* FUN_0043c020 — calls ROLClient_Connect */
        {"SVC_ConnTrig1",    0x0043b1a0},  /* FUN_0043b1a0 — caller of ConnectDisp */
        {"SVC_ConnTrig2",    0x00440520},  /* FUN_00440520 — caller of ConnectDisp */
        {"SVC_ConnTrig3",    0x0044ca80},  /* FUN_0044ca80 — caller of ConnectDisp */
        /* Task system probes (CListener investigation) */
        {"SVC_TskSched",     0x0045eda0},  /* FUN_0045eda0 — task scheduler entry */
        {"SVC_TskCh2",       0x00452bb0},  /* FUN_00452bb0 — sched_chain_2 (inserts into exec list) */
        {"SVC_TskGuard",     0x004638b0},  /* FUN_004638b0 — guard: checks +0x10/+0x14 */
        {"SVC_TskVt2",       0x004606c0},  /* FUN_004606c0 — CListener vtable[2] (schedule w/ delay) */
        {"SVC_TskExec",      0x00464200},  /* FUN_00464200 — CListener vtable6[1] (main exec fn) */
        {"SVC_TskLoop",      0x00462590},  /* FUN_00462590 — CListener vtable6[4] (connect loop) */
        {"SVC_TskDisp",      0x0046a2d0},  /* FUN_0046a2d0 — called from vtable[2] */
        {"SVC_TskWork",      0x00427860},  /* FUN_00427860 — ListenVpn wrapper? called after VT2 */
        {"SVC_TskConn",      0x00414150},  /* FUN_00414150 — called after FUN_00427860 in TSK_EXEC */
        /* Readiness check chain probes */
        {"SVC_RdyChk",       0x00469490},  /* FUN_00469490 — readiness check (param_1=4 for CListener) */
        {"SVC_RdyD14",       0x0046d140},  /* FUN_0046d140 — CListener-specific check 1 */
        {"SVC_RdyD11",       0x0046d110},  /* FUN_0046d110 — CListener-specific check 2 */
        /* Also probe the TEST EAX after vtable[2] call (at 0x004644bc in TSK_EXEC) */
        {"SVC_VT2Ret",       0x004644bc},  /* TEST EAX,EAX after vtable[2] — log residual EAX */
        /* Keep only Chk07 (the failing one) and Chk08 (first after) */
        {"SVC_Chk07",        0x0046d3d0},  /* check 7: FUN_0046d3d0 — THE FAILING CHECK */
        {"SVC_Chk08",        0x0046cf10},  /* check 8: FUN_0046cf10 — should fire if Chk07 passes */
        /* Registration response parsing */
        {"SVC_RegPrs",       0x00432e80},  /* FUN_00432e80 — parse registration response (case 9) */
        {"SVC_RegWrt",       0x0046c6b0},  /* FUN_0046c6b0 — WRITE ServerPassword to registry */
        {NULL, 0}
    };
    int svc_added = 0;
    for (int i = 0; svc_bps[i].name && rol_bp_count < ROL_MAX_BP; i++) {
        unsigned char *fn = (unsigned char *)(DWORD_PTR)svc_bps[i].addr;
        int idx = rol_bp_count++;
        rol_bps[idx].name = svc_bps[i].name;
        rol_bps[idx].addr = fn;
        rol_bps[idx].orig_byte = *fn;
        rol_bps[idx].count = 0;
        rol_bps[idx].active = 1;
        DWORD old2;
        VirtualProtect(fn, 1, PAGE_EXECUTE_READWRITE, &old2);
        *fn = 0xCC;
        VirtualProtect(fn, 1, old2, &old2);
        FlushInstructionCache(GetCurrentProcess(), fn, 1);
        svc_added++;
    }
    wsprintfA(buf, "SVC breakpoints: %d added (total %d)", svc_added, rol_bp_count);
    dbg(buf);

    tramp_listen_vpn = (unsigned char *)1; /* sentinel: installed */
}

static int rol_counts_dumped = 0;

static void dump_rol_counts(void)
{
    if (rol_counts_dumped >= 3) return;
    rol_counts_dumped++;

    char buf[1024];
    int pos = wsprintfA(buf, "ROL_CALLS:");
    for (int i = 0; i < rol_bp_count; i++) {
        if (rol_bps[i].count > 0) {
            pos += wsprintfA(buf + pos, " %s=%ld", rol_bps[i].name, rol_bps[i].count);
        }
        if (pos > 900) break;
    }
    /* Also log zero-count functions for completeness */
    pos += wsprintfA(buf + pos, " | NEVER:");
    for (int i = 0; i < rol_bp_count; i++) {
        if (rol_bps[i].count == 0) {
            pos += wsprintfA(buf + pos, " %s", rol_bps[i].name);
        }
        if (pos > 900) break;
    }
    log_evt_raw(buf);
}

/*
 * Hook for FUN_0043c020 (the connect function that calls ROLClient_Connect)
 * Params: IP bytes (4 uints) + mode
 * If this is never called, ROLClient_Connect is never invoked.
 */
static unsigned char __attribute__((thiscall))
hook_connect(void *self, unsigned int p1, unsigned int p2, unsigned int p3, unsigned int p4, unsigned int p5)
{
    char buf[128];
    wsprintfA(buf, "CONNECT called! ip=%u.%u.%u.%u mode=%u self=%p",
              p1 & 0xFF, p2 & 0xFF, p3 & 0xFF, p4 & 0xFF, p5, self);
    log_evt_raw(buf);
    return ((ConnectFn)tramp_conn)(self, p1, p2, p3, p4, p5);
}

/* Write a 5-byte JMP at 'src' to 'dst'. Returns 0 on failure. */
static int write_jmp(void *src, void *dst, int patch_len)
{
    DWORD old;
    if (!VirtualProtect(src, patch_len, PAGE_EXECUTE_READWRITE, &old))
        return 0;
    unsigned char *p = (unsigned char *)src;
    p[0] = 0xE9; /* JMP rel32 */
    *(int *)(p + 1) = (int)((unsigned char *)dst - (p + 5));
    /* NOP any remaining bytes */
    for (int i = 5; i < patch_len; i++) p[i] = 0x90;
    VirtualProtect(src, patch_len, old, &old);
    FlushInstructionCache(GetCurrentProcess(), src, patch_len);
    return 1;
}

/* Build trampoline: copy original bytes + JMP back to original+len */
static unsigned char *make_trampoline(void *original, int len)
{
    unsigned char *t = (unsigned char *)VirtualAlloc(NULL, 32,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!t) return NULL;
    memcpy(t, original, len);
    t[len] = 0xE9; /* JMP rel32 */
    *(int *)(t + len + 1) = (int)((unsigned char *)original + len - (t + len + 5));
    FlushInstructionCache(GetCurrentProcess(), t, len + 5);
    return t;
}

static void install_event_hooks(void)
{
    HMODULE exe = GetModuleHandle(NULL);
    if (!exe) return;

    /* Offsets from image base (0x00400000) */
    unsigned char *evt_fn    = (unsigned char *)exe + 0x44b50;  /* FUN_00444b50 */
    unsigned char *fsm_fn    = (unsigned char *)exe + 0x4bfe0;  /* FUN_0044bfe0 */
    unsigned char *conn_fn   = (unsigned char *)exe + 0x3c020;  /* FUN_0043c020 */
    unsigned char *notify_fn = (unsigned char *)exe + 0x4b080;  /* FUN_0044b080 */

    /* Verify first bytes match expected values */
    if (evt_fn[0] != 0x55 || evt_fn[1] != 0x8B || evt_fn[2] != 0xEC) {
        dbg("event hook: prologue mismatch, skipping");
        return;
    }
    if (fsm_fn[0] != 0x55 || fsm_fn[1] != 0x8B || fsm_fn[2] != 0xEC) {
        dbg("state hook: prologue mismatch, skipping");
        return;
    }
    if (conn_fn[0] != 0x55 || conn_fn[1] != 0x8B || conn_fn[2] != 0xEC) {
        dbg("connect hook: prologue mismatch, skipping");
        return;
    }
    /* FUN_0044b080: 56 8B F1 8B 86 00 51 00 00 (PUSH ESI; MOV ESI,ECX; MOV EAX,[ESI+0x5100]) */
    if (notify_fn[0] != 0x56 || notify_fn[1] != 0x8B || notify_fn[2] != 0xF1) {
        char msg[128];
        wsprintfA(msg, "notify hook: prologue mismatch: %02x %02x %02x (expected 56 8B F1)",
                  notify_fn[0], notify_fn[1], notify_fn[2]);
        dbg(msg);
    }

    /* Build trampolines (save original bytes + JMP back) */
    tramp_evt    = make_trampoline(evt_fn, 6);     /* 55 8B EC 8B 45 08 */
    tramp_fsm    = make_trampoline(fsm_fn, 6);     /* 55 8B EC 51 53 56 */
    tramp_conn   = make_trampoline(conn_fn, 5);    /* 55 8B EC 6A FF */
    tramp_notify = make_trampoline(notify_fn, 9);  /* 56 8B F1 8B 86 00 51 00 00 */

    if (!tramp_evt || !tramp_fsm || !tramp_conn) {
        dbg("hook: trampoline alloc failed");
        return;
    }

    /* Overwrite originals with JMP to our hooks */
    if (!write_jmp(evt_fn, (void *)hook_event_dispatch, 6)) {
        dbg("hook: event JMP write failed");
        return;
    }
    if (!write_jmp(fsm_fn, (void *)hook_state_machine, 6)) {
        dbg("hook: FSM JMP write failed");
        return;
    }
    if (!write_jmp(conn_fn, (void *)hook_connect, 5)) {
        dbg("hook: connect JMP write failed");
        return;
    }
    if (tramp_notify) {
        if (!write_jmp(notify_fn, (void *)hook_notify_rol, 9)) {
            dbg("hook: notify JMP write failed");
        }
    }

    {
        char buf[256];
        wsprintfA(buf, "hooks installed: evt=%p fsm=%p conn=%p notify=%p",
                  evt_fn, fsm_fn, conn_fn, notify_fn);
        dbg(buf);
    }
}

/* Parent address for counter logging (captured from ENQ_TARGET) */
static volatile DWORD g_pump_parent = 0;

static DWORD WINAPI regwrite_thread(LPVOID param)
{
    (void)param;
    /* Diagnose WHY this thread can't access HKLM */
    Sleep(2000); /* wait for service to settle */
    {
        char buf[256];
        HANDLE tok = NULL;
        BOOL ok = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, FALSE, &tok);
        wsprintfA(buf, "REGDIAG: OpenThreadToken=%d err=%lu", ok, ok ? 0 : GetLastError());
        dbg(buf);
        if (tok) {
            TOKEN_TYPE tt;
            DWORD len;
            ok = GetTokenInformation(tok, TokenType, &tt, sizeof(tt), &len);
            wsprintfA(buf, "REGDIAG: ThreadTokenType=%d (1=Primary,2=Impersonation)", ok ? tt : -1);
            dbg(buf);
            SECURITY_IMPERSONATION_LEVEL sil;
            ok = GetTokenInformation(tok, TokenImpersonationLevel, &sil, sizeof(sil), &len);
            wsprintfA(buf, "REGDIAG: ImpersonationLevel=%d (0=Anon,1=Ident,2=Imp,3=Deleg)", ok ? sil : -1);
            dbg(buf);
            CloseHandle(tok);
        }
        /* Try RevertToSelf to drop any impersonation */
        ok = RevertToSelf();
        wsprintfA(buf, "REGDIAG: RevertToSelf=%d", ok);
        dbg(buf);
        /* Now try HKLM again */
        HKEY hk;
        LONG r = RegCreateKeyExW(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Famatech\\RadminVPN\\1.0\\Registration",
            0, NULL, 0, KEY_ALL_ACCESS, NULL, &hk, NULL);
        wsprintfA(buf, "REGDIAG: after RevertToSelf HKLM=%ld", r);
        dbg(buf);
        if (r == ERROR_SUCCESS) {
            dbg("REGDIAG: *** RevertToSelf FIXED IT ***");
            if (g_reg_hk) RegCloseKey(g_reg_hk);
            g_reg_hk = hk;
        }
    }
    for (;;) {
        Sleep(100);
        if (g_regwrite_pending && g_reg_hk) {
            LONG r = RegSetValueExW(g_reg_hk, L"ServerPassword", 0, REG_BINARY,
                                    g_regwrite_buf, g_regwrite_size);
            char buf[128];
            wsprintfA(buf, "REGWRITER: wrote via pre-opened handle size=%d result=%ld",
                      g_regwrite_size, r);
            dbg(buf);
            g_regwrite_pending = 0;
        }
    }
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved)
{
    (void)inst; (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        dbg("adapter_hook.dll: DllMain called");
        HMODULE exe = GetModuleHandle(NULL);
        if (!exe) {
            dbg("adapter_hook.dll: GetModuleHandle(NULL) returned NULL!");
        } else {
            dbg("adapter_hook.dll: patching IAT...");
            patch_iat(exe);
            if (real_GetAdaptersAddresses) {
                dbg("adapter_hook.dll: hook installed OK");
            } else {
                dbg("adapter_hook.dll: hook FAILED - real_GetAdaptersAddresses is NULL");
            }
        }
        /* Start deferred registry writer thread (deferred — not in DllMain due to loader lock) */
        CreateThread(NULL, 0, regwrite_thread, NULL, 0, NULL);

        /* Pre-open HKLM Registration key (threads lose HKLM access later) */
        {
            LONG r_test = RegCreateKeyExW(HKEY_LOCAL_MACHINE,
                L"SOFTWARE\\Famatech\\RadminVPN\\1.0\\Registration",
                0, NULL, 0, KEY_ALL_ACCESS, NULL, &g_reg_hk, NULL);
            char tbuf[128];
            wsprintfA(tbuf, "DLLMAIN_REG: pre-opened handle=%p result=%ld",
                      (void*)g_reg_hk, r_test);
            dbg(tbuf);
        }

        /* Install event/state logging hooks */
        install_event_hooks();

        /* Detour CreateThread to log thread storm */
        {
            HMODULE k32 = GetModuleHandleA("kernel32.dll");
            if (k32) {
                unsigned char *fn = (unsigned char *)GetProcAddress(k32, "CreateThread");
                if (fn) {
                    tramp_ct = make_trampoline(fn, 5);
                    if (tramp_ct && write_jmp(fn, (void *)hook_CreateThread_fn, 5))
                        dbg("detoured CreateThread");
                }
            }
        }

        /* Hook ROL DLL exports (may fail if not loaded yet — retry from notify hook) */
        install_rol_hooks();

        /* Detour WSASocketW in ws2_32.dll directly (affects ALL callers) */
        {
            HMODULE ws2 = GetModuleHandleA("ws2_32.dll");
            if (!ws2) ws2 = LoadLibraryA("ws2_32.dll");
            if (ws2) {
                unsigned char *fn = (unsigned char *)GetProcAddress(ws2, "WSASocketW");
                if (fn) {
                    /* Save real function pointer before we overwrite */
                    static unsigned char *tramp_wsa = NULL;
                    tramp_wsa = make_trampoline(fn, 5);
                    if (tramp_wsa) {
                        real_WSASocketW = (void *)tramp_wsa;
                        if (write_jmp(fn, (void *)hook_WSASocketW, 5)) {
                            dbg("detoured WSASocketW in ws2_32.dll (IPv6 block active)");
                        } else {
                            dbg("WSASocketW detour write failed");
                        }
                    }
                } else {
                    dbg("WSASocketW not found in ws2_32.dll");
                }
            }
        }
    }
    return TRUE;
}
