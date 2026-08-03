#include <winsock2.h>
#include <windows.h>
#include <cstdio>
#include <tlhelp32.h>
#include <psapi.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <winreg.h>
#include <shlobj.h>
#include <shellapi.h>
#include <winbase.h>
#include <aclapi.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>
#include <msi.h>
#include <setupapi.h>
#include <cfgmgr32.h>
#include <devguid.h>
#include <winhttp.h>
#include <ws2tcpip.h>
#include <mmsystem.h>
#include <commdlg.h>
#include <commctrl.h>


int main() {
    printf("Category B: Many Imports\n");
    printf("This binary imports functions from many Windows DLLs\n\n");

    // kernel32
    DWORD pid = GetCurrentProcessId();
    HANDLE hProc = GetCurrentProcess();
    DWORD tick = GetTickCount();
    SYSTEMTIME st;
    GetSystemTime(&st);
    char sysDir[MAX_PATH];
    GetSystemDirectoryA(sysDir, MAX_PATH);
    DWORD sector, clusters, freeClusters, totalClusters;
    GetDiskFreeSpaceA("C:\\", &sector, &clusters, &freeClusters, &totalClusters);
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    GlobalMemoryStatusEx(&memInfo);
    printf("PID: %lu, Ticks: %lu\n", pid, tick);
    printf("System Dir: %s\n", sysDir);
    printf("Total Physical Memory: %llu MB\n", memInfo.ullTotalPhys / (1024*1024));

    // user32
    HWND hwnd = GetDesktopWindow();
    int screenW = GetSystemMetrics(SM_CXSCREEN);
    int screenH = GetSystemMetrics(SM_CYSCREEN);
    UINT dpi = GetDpiForSystem();
    printf("Screen: %dx%d, DPI: %u\n", screenW, screenH, dpi);

    // advapi32
    HKEY hKey;
    LONG res = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0,
        KEY_READ, &hKey);
    if (res == ERROR_SUCCESS) {
        char productName[256] = {0};
        DWORD size = sizeof(productName);
        RegQueryValueExA(hKey, "ProductName", NULL, NULL,
            (LPBYTE)productName, &size);
        printf("Windows: %s\n", productName);
        RegCloseKey(hKey);
    }

    // shell32
    char appData[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appData);
    printf("AppData: %s\n", appData);

    // iphlpapi
    IP_ADAPTER_INFO adapterInfo[16];
    DWORD bufLen = sizeof(adapterInfo);
    GetAdaptersInfo(adapterInfo, &bufLen);

    // gdi32
    HDC hdc = GetDC(NULL);
    int bitsPP = GetDeviceCaps(hdc, BITSPIXEL);
    int planes = GetDeviceCaps(hdc, PLANES);
    ReleaseDC(NULL, hdc);
    printf("Display: %d bpp, %d planes\n", bitsPP, planes);

    // ws2_32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    char hostName[256];
    gethostname(hostName, sizeof(hostName));
    printf("Hostname: %s\n", hostName);
    struct addrinfo hints = {0}, *result;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    getaddrinfo("localhost", "80", &hints, &result);
    if (result) freeaddrinfo(result);
    WSACleanup();

    // wintrust
    WINTRUST_FILE_INFO fileInfo = {0};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = L"test.exe";
    GUID actionId = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA wintrustData = {0};
    wintrustData.cbStruct = sizeof(wintrustData);
    wintrustData.pPolicyCallbackData = NULL;
    wintrustData.pSIPClientData = NULL;
    wintrustData.dwUIChoice = WTD_UI_NONE;
    wintrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    wintrustData.dwUnionChoice = WTD_CHOICE_FILE;
    wintrustData.pFile = &fileInfo;
    wintrustData.dwStateAction = WTD_STATEACTION_VERIFY;
    printf("WinTrust structures initialized\n");

    // crypt32
    HCERTSTORE hStore = CertOpenSystemStoreA(0, "ROOT");
    if (hStore) {
        DWORD certCount = 0;
        PCCERT_CONTEXT pCert = NULL;
        while ((pCert = CertEnumCertificatesInStore(hStore, pCert)) != NULL) {
            certCount++;
        }
        printf("Root CA certificates: %lu\n", certCount);
        CertCloseStore(hStore, 0);
    }

    // mmsystem
    UINT devs = waveOutGetNumDevs();
    printf("Wave output devices: %u\n", devs);

    // comdlg32
    OPENFILENAMEA ofn;
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    printf("Common dialog structures initialized\n");

    printf("\nAll imports resolved successfully.\n");
    return 0;
}
