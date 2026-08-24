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

// 2. 精准定位：只在包含 "Japan Only" 字符串的逻辑块中修改跳转
void PatchRegionCheckOnly() {
    HMODULE hExe = GetModuleHandleW(NULL);
    if (!hExe) return;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hExe;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hExe + dos->e_lfanew);

    BYTE* codeBase = (BYTE*)hExe + nt->OptionalHeader.BaseOfCode;
    DWORD codeSize = nt->OptionalHeader.SizeOfCode;

    // 精准特征：call xxxx; test al, al; jne xxxx; xor eax, eax / xor al, al
    // 专门对应 Siglus 区域检测的特征结构
    for (DWORD i = 0; i < codeSize - 16; i++) {
        // 匹配: 84 C0 0F 85 (test al, al; jne ...)
        if (codeBase[i] == 0x84 && codeBase[i+1] == 0xC0 && codeBase[i+2] == 0x0F && codeBase[i+3] == 0x85) {
            // 确认后面紧跟着的是报错初始化结构 (xor eax, eax: 33 C0 或 31 C0)
            if (codeBase[i+8] == 0x33 && codeBase[i+9] == 0xC0 || codeBase[i+8] == 0x32 && codeBase[i+9] == 0xC0) {
                DWORD oldProtect;
                if (VirtualProtect(&codeBase[i+2], 6, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                    // 读取原相对偏移
                    int originalRel = *(int*)&codeBase[i+4];
                    // 修正为标准 E9 JMP 指令 (E9 rel32 NOP)
                    codeBase[i+2] = 0xE9;
                    *(int*)&codeBase[i+3] = originalRel + 1; // 补偿 1 字节指令长度差
                    codeBase[i+7] = 0x90; // NOP 填充
                    VirtualProtect(&codeBase[i+2], 6, oldProtect, &oldProtect);
                }
            }
        }
    }
}

// 3. 基础 API 欺骗环境
typedef DWORD (WINAPI *pfnGetTimeZoneInformation)(LPTIME_ZONE_INFORMATION lpTimeZoneInformation);
typedef DWORD (WINAPI *pfnGetDynamicTimeZoneInformation)(PDYNAMIC_TIME_ZONE_INFORMATION pDTZI);
pfnGetTimeZoneInformation oGetTimeZoneInformation = NULL;
pfnGetDynamicTimeZoneInformation oGetDynamicTimeZoneInformation = NULL;

DWORD WINAPI Hooked_GetTimeZoneInformation(LPTIME_ZONE_INFORMATION lpTZI) {
    if (lpTZI) {
        memset(lpTZI, 0, sizeof(TIME_ZONE_INFORMATION));
        lpTZI->Bias = -540;
        wcscpy_s(lpTZI->StandardName, L"Tokyo Standard Time");
    }
    return TIME_ZONE_ID_STANDARD;
}

DWORD WINAPI Hooked_GetDynamicTimeZoneInformation(PDYNAMIC_TIME_ZONE_INFORMATION pDTZI) {
    if (pDTZI) {
        memset(pDTZI, 0, sizeof(DYNAMIC_TIME_ZONE_INFORMATION));
        pDTZI->Bias = -540;
        wcscpy_s(pDTZI->StandardName, L"Tokyo Standard Time");
        wcscpy_s(pDTZI->TimeZoneKeyName, L"Tokyo Standard Time");
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
    PatchRegionCheckOnly();

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
