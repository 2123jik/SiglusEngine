#include <windows.h>
#include <MinHook.h>

// ==========================================
// 1. 系统 version.dll 的函数转发
// 保证系统正常的版本查询函数不失效
// ==========================================
#pragma comment(linker, "/EXPORT:GetFileVersionInfoA=C:\\Windows\\System32\\version.GetFileVersionInfoA")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoByHandle=C:\\Windows\\System32\\version.GetFileVersionInfoByHandle")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoExA=C:\\Windows\\System32\\version.GetFileVersionInfoExA")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoExW=C:\\Windows\\System32\\version.GetFileVersionInfoExW")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoSizeA=C:\\Windows\\System32\\version.GetFileVersionInfoSizeA")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoSizeExA=C:\\Windows\\System32\\version.GetFileVersionInfoSizeExA")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoSizeExW=C:\\Windows\\System32\\version.GetFileVersionInfoSizeExW")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoSizeW=C:\\Windows\\System32\\version.GetFileVersionInfoSizeW")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoW=C:\\Windows\\System32\\version.GetFileVersionInfoW")
#pragma comment(linker, "/EXPORT:VerFindFileA=C:\\Windows\\System32\\version.VerFindFileA")
#pragma comment(linker, "/EXPORT:VerFindFileW=C:\\Windows\\System32\\version.VerFindFileW")
#pragma comment(linker, "/EXPORT:VerInstallFileA=C:\\Windows\\System32\\version.VerInstallFileA")
#pragma comment(linker, "/EXPORT:VerInstallFileW=C:\\Windows\\System32\\version.VerInstallFileW")
#pragma comment(linker, "/EXPORT:VerLanguageNameA=C:\\Windows\\System32\\version.VerLanguageNameA")
#pragma comment(linker, "/EXPORT:VerLanguageNameW=C:\\Windows\\System32\\version.VerLanguageNameW")
#pragma comment(linker, "/EXPORT:VerQueryValueA=C:\\Windows\\System32\\version.VerQueryValueA")
#pragma comment(linker, "/EXPORT:VerQueryValueW=C:\\Windows\\System32\\version.VerQueryValueW")

// ==========================================
// 2. 原函数指针声明
// ==========================================
typedef DWORD (WINAPI *pfnGetTimeZoneInformation)(LPTIME_ZONE_INFORMATION lpTimeZoneInformation);
typedef UINT  (WINAPI *pfnGetACP)();
typedef UINT  (WINAPI *pfnGetOEMCP)();
typedef LCID  (WINAPI *pfnGetSystemDefaultLCID)();
typedef LCID  (WINAPI *pfnGetUserDefaultLCID)();
typedef LCID  (WINAPI *pfnGetThreadLocale)();

pfnGetTimeZoneInformation oGetTimeZoneInformation = NULL;
pfnGetACP                  oGetACP                  = NULL;
pfnGetOEMCP                oGetOEMCP                = NULL;
pfnGetSystemDefaultLCID    oGetSystemDefaultLCID    = NULL;
pfnGetUserDefaultLCID      oGetUserDefaultLCID      = NULL;
pfnGetThreadLocale         oGetThreadLocale         = NULL;

// ==========================================
// 3. 拦截函数（伪造日本环境）
// ==========================================

// 欺骗时区：将时区 Bias 强制篡改为 -540（UTC+9 日本时间），名称设为 Tokyo
DWORD WINAPI Hooked_GetTimeZoneInformation(LPTIME_ZONE_INFORMATION lpTZI) {
    DWORD res = oGetTimeZoneInformation(lpTZI);
    if (lpTZI) {
        lpTZI->Bias = -540; // -540 分钟即 UTC+9 (日本时区)
        lpTZI->StandardBias = 0;
        lpTZI->DaylightBias = 0;
        wcscpy_s(lpTZI->StandardName, L"Tokyo Standard Time");
        wcscpy_s(lpTZI->DaylightName, L"Tokyo Daylight Time");
    }
    return TIME_ZONE_ID_STANDARD;
}

// 欺骗代码页：强制返回 932 (日文 Shift-JIS)
UINT WINAPI Hooked_GetACP() {
    return 932;
}

UINT WINAPI Hooked_GetOEMCP() {
    return 932;
}

// 欺骗 Locale ID：强制返回 0x0411 (日文语言代码 1041)
LCID WINAPI Hooked_GetSystemDefaultLCID() {
    return 0x0411;
}

LCID WINAPI Hooked_GetUserDefaultLCID() {
    return 0x0411;
}

LCID WINAPI Hooked_GetThreadLocale() {
    return 0x0411;
}

// ==========================================
// 4. 安装 Hook
// ==========================================
void InstallLocaleHooks() {
    if (MH_Initialize() != MH_OK) {
        return;
    }

    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel32) return;

    // 挂钩时区检测
    MH_CreateHookApi(L"kernel32.dll", "GetTimeZoneInformation", Hooked_GetTimeZoneInformation, (void**)&oGetTimeZoneInformation);
    
    // 挂钩代码页检测
    MH_CreateHookApi(L"kernel32.dll", "GetACP", Hooked_GetACP, (void**)&oGetACP);
    MH_CreateHookApi(L"kernel32.dll", "GetOEMCP", Hooked_GetOEMCP, (void**)&oGetOEMCP);
    
    // 挂钩区域/语言检测
    MH_CreateHookApi(L"kernel32.dll", "GetSystemDefaultLCID", Hooked_GetSystemDefaultLCID, (void**)&oGetSystemDefaultLCID);
    MH_CreateHookApi(L"kernel32.dll", "GetUserDefaultLCID", Hooked_GetUserDefaultLCID, (void**)&oGetUserDefaultLCID);
    MH_CreateHookApi(L"kernel32.dll", "GetThreadLocale", Hooked_GetThreadLocale, (void**)&oGetThreadLocale);

    // 启用所有 Hook
    MH_EnableHook(MH_ALL_HOOKS);
}

// ==========================================
// 5. DLL 入口点
// ==========================================
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        InstallLocaleHooks();
    }
    return TRUE;
}
