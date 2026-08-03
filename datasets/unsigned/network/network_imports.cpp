#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <winhttp.h>
#include <stdio.h>

// Network API imports - does NOT perform any actual networking
// Just imports and calls initialization/enumeration functions

int main() {
    printf("Category I: Network API Imports\n");
    printf("Imports network DLLs but performs no actual network activity\n\n");

    // Winsock initialization
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    printf("WSAStartup: %d\n", result);

    if (result == 0) {
        char hostName[256] = {0};
        gethostname(hostName, sizeof(hostName));
        printf("Hostname: %s\n", hostName);

        // Get address info (local only)
        struct addrinfo hints = {0}, *res = NULL;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_PASSIVE;

        int gaiResult = getaddrinfo(NULL, "0", &hints, &res);
        if (gaiResult == 0 && res) {
            char addrStr[INET_ADDRSTRLEN];
            struct sockaddr_in* sin = (struct sockaddr_in*)res->ai_addr;
            inet_ntop(AF_INET, &sin->sin_addr, addrStr, sizeof(addrStr));
            printf("Local address: %s\n", addrStr);
            freeaddrinfo(res);
        }

        WSACleanup();
    }

    // IP Helper API - enumerate adapters (local only)
    IP_ADAPTER_INFO* pAdapterInfo = NULL;
    ULONG outBufLen = 0;
    DWORD dwRetVal = GetAdaptersInfo(pAdapterInfo, &outBufLen);
    if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
        pAdapterInfo = (IP_ADAPTER_INFO*)malloc(outBufLen);
        if (pAdapterInfo) {
            dwRetVal = GetAdaptersInfo(pAdapterInfo, &outBufLen);
            if (dwRetVal == NO_ERROR) {
                IP_ADAPTER_INFO* pAdapter = pAdapterInfo;
                int count = 0;
                while (pAdapter) {
                    printf("  Adapter[%d]: %s (Type: %lu)\n",
                        count++, pAdapter->AdapterName, pAdapter->Type);
                    pAdapter = pAdapter->Next;
                }
            }
            free(pAdapterInfo);
        }
    }

    // WinHTTP - just create and close a session
    HINTERNET hSession = WinHttpOpen(L"DefenderAtlas/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    if (hSession) {
        printf("WinHTTP session created successfully\n");
        WinHttpCloseHandle(hSession);
    }

    // Socket creation (not connected)
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s != INVALID_SOCKET) {
        printf("Socket created (not connected)\n");
        closesocket(s);
    }

    // UDP socket
    SOCKET udp = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp != INVALID_SOCKET) {
        printf("UDP socket created (not connected)\n");
        closesocket(udp);
    }

    printf("\nNo network connections were established.\n");
    printf("=== Complete ===\n");
    return 0;
}
