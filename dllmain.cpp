#include <windows.h>
#include <MinHook.h>

// 1. 系统 version.dll 转发
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

// 2. 内存特征码自动打补丁（直接在内存中干掉所有 JNE 报错跳转）
void AutoPatchMemory() {
    HMODULE hExe = GetModuleHandleW(NULL);
    if (!hExe) return;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hExe;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hExe + dos->e_lfanew);
    
    // 遍历代码段 (.text)
    BYTE* base = (BYTE*)hExe + nt->OptionalHeader.BaseOfCode;
    DWORD size = nt->OptionalHeader.SizeOfCode;

    // 搜索特征：84 C0 0F 85 ?? ?? ?? ?? (test al, al; jne ...)
    // 遇到判断直接把 0F 85 (jne) 改为 90 E9 (nop; jmp) 强制通过
    for (DWORD i = 0; i < size - 8; i++) {
        if (base[i] == 0x84 && base[i+1] == 0xC0 && base[i+2] == 0x0F && base[i+3] == 0x85) {
            DWORD oldProtect;
            if (VirtualProtect(&base[i+2], 6, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                // 0F 85 xx xx xx xx -> 90 E9 xx xx xx xx (转成无条件跳转 jmp)
                base[i+2] = 0x90;
                base[i+3] = 0xE9;
                VirtualProtect(&base[i+2], 6, oldProtect, &oldProtect);
            }
        }
    }
}

// 3. API 欺骗：补充新版时区与动态时区 API
typedef DWORD (WINAPI *pfnGetDynamicTimeZoneInformation)(PDYNAMIC_TIME_ZONE_INFORMATION pDTZI);
pfnGetDynamicTimeZoneInformation oGetDynamicTimeZoneInformation = NULL;

DWORD WINAPI Hooked_GetDynamicTimeZoneInformation(PDYNAMIC_TIME_ZONE_INFORMATION pDTZI) {
    if (pDTZI) {
        memset(pDTZI, 0, sizeof(DYNAMIC_TIME_ZONE_INFORMATION));
        pDTZI->Bias = -540; // UTC+9
        wcscpy_s(pDTZI->StandardName, L"Tokyo Standard Time");
        wcscpy_s(pDTZI->TimeZoneKeyName, L"Tokyo Standard Time");
    }
    return TIME_ZONE_ID_STANDARD;
}

typedef DWORD (WINAPI *pfnGetTimeZoneInformation)(LPTIME_ZONE_INFORMATION lpTimeZoneInformation);
pfnGetTimeZoneInformation oGetTimeZoneInformation = NULL;

DWORD WINAPI Hooked_GetTimeZoneInformation(LPTIME_ZONE_INFORMATION lpTZI) {
    if (lpTZI) {
        memset(lpTZI, 0, sizeof(TIME_ZONE_INFORMATION));
        lpTZI->Bias = -540; // UTC+9
        wcscpy_s(lpTZI->StandardName, L"Tokyo Standard Time");
    }
    return TIME_ZONE_ID_STANDARD;
}

UINT WINAPI Hooked_GetACP() { return 932; }
UINT WINAPI Hooked_GetOEMCP() { return 932; }
LCID WINAPI Hooked_GetSystemDefaultLCID() { return 0x0411; }
LCID WINAPI Hooked_GetUserDefaultLCID() { return 0x0411; }
LANGID WINAPI Hooked_GetUserDefaultUILanguage() { return 0x0411; }
LANGID WINAPI Hooked_GetSystemDefaultUILanguage() { return 0x0411; }

void InstallHooks() {
    // 先做内存扫描自动打补丁（双重保险）
    AutoPatchMemory();

    if (MH_Initialize() != MH_OK) return;

    MH_CreateHookApi(L"kernel32.dll", "GetTimeZoneInformation", Hooked_GetTimeZoneInformation, (void**)&oGetTimeZoneInformation);
    MH_CreateHookApi(L"kernel32.dll", "GetDynamicTimeZoneInformation", Hooked_GetDynamicTimeZoneInformation, (void**)&oGetDynamicTimeZoneInformation);
    MH_CreateHookApi(L"kernel32.dll", "GetACP", Hooked_GetACP, NULL);
    MH_CreateHookApi(L"kernel32.dll", "GetOEMCP", Hooked_GetOEMCP, NULL);
    MH_CreateHookApi(L"kernel32.dll", "GetSystemDefaultLCID", Hooked_GetSystemDefaultLCID, NULL);
    MH_CreateHookApi(L"kernel32.dll", "GetUserDefaultLCID", Hooked_GetUserDefaultLCID, NULL);
    MH_CreateHookApi(L"kernel32.dll", "GetUserDefaultUILanguage", Hooked_GetUserDefaultUILanguage, NULL);
    MH_CreateHookApi(L"kernel32.dll", "GetSystemDefaultUILanguage", Hooked_GetSystemDefaultUILanguage, NULL);

    MH_EnableHook(MH_ALL_HOOKS);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        InstallHooks();
    }
    return TRUE;
}
