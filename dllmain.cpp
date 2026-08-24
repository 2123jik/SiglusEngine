#include <windows.h>
#include <MinHook.h>

// 转发系统 version.dll 的函数，避免系统功能失效
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

// 伪造日本时区 (UTC+9, Tokyo)
DWORD WINAPI Hooked_GetTimeZoneInformation(LPTIME_ZONE_INFORMATION lpTZI) {
    DWORD res = oGetTimeZoneInformation(lpTZI);
    if (lpTZI) {
        lpTZI->Bias = -540;
        lpTZI->StandardBias = 0;
        lpTZI->DaylightBias = 0;
        wcscpy_s(lpTZI->StandardName, L"Tokyo Standard Time");
        wcscpy_s(lpTZI->DaylightName, L"Tokyo Daylight Time");
    }
    return TIME_ZONE_ID_STANDARD;
}

// 伪造日文代码页 932
UINT WINAPI Hooked_GetACP()   { return 932; }
UINT WINAPI Hooked_GetOEMCP() { return 932; }

// 伪造日文 Locale 0x0411
LCID WINAPI Hooked_GetSystemDefaultLCID() { return 0x0411; }
LCID WINAPI Hooked_GetUserDefaultLCID()   { return 0x0411; }
LCID WINAPI Hooked_GetThreadLocale()      { return 0x0411; }

void InstallLocaleHooks() {
    if (MH_Initialize() != MH_OK) return;
    MH_CreateHookApi(L"kernel32.dll", "GetTimeZoneInformation", Hooked_GetTimeZoneInformation, (void**)&oGetTimeZoneInformation);
    MH_CreateHookApi(L"kernel32.dll", "GetACP", Hooked_GetACP, (void**)&oGetACP);
    MH_CreateHookApi(L"kernel32.dll", "GetOEMCP", Hooked_GetOEMCP, (void**)&oGetOEMCP);
    MH_CreateHookApi(L"kernel32.dll", "GetSystemDefaultLCID", Hooked_GetSystemDefaultLCID, (void**)&oGetSystemDefaultLCID);
    MH_CreateHookApi(L"kernel32.dll", "GetUserDefaultLCID", Hooked_GetUserDefaultLCID, (void**)&oGetUserDefaultLCID);
    MH_CreateHookApi(L"kernel32.dll", "GetThreadLocale", Hooked_GetThreadLocale, (void**)&oGetThreadLocale);
    MH_EnableHook(MH_ALL_HOOKS);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        InstallLocaleHooks();
    }
    return TRUE;
}
