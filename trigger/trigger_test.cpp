#define UNICODE
#define _UNICODE

#include <windows.h>
#include <shobjidl.h>

#include <iostream>
#include <string>

#pragma comment(lib, "ole32.lib")

static void PrintHr(const wchar_t* operation, HRESULT hr)
{
    std::wcout << operation
               << L": HRESULT=0x"
               << std::hex
               << static_cast<unsigned long>(hr)
               << std::dec
               << L"\n";
}

int wmain(int argc, wchar_t* argv[])
{
    if (argc != 3) {
        std::wcerr
            << L"Usage:\n"
            << L"  trigger_test.exe <local-file> <source-url>\n\n"
            << L"Example:\n"
            << L"  trigger_test.exe C:\\Users\\cruiz\\Downloads\\mspaint_test.exe "
            << L"https://example.com/mspaint.exe\n";

        return 1;
    }

    const std::wstring localPath = argv[1];
    const std::wstring sourceUrl = argv[2];

    // IAttachmentExecute::Save expects the file to already exist at
    // the path supplied to SetLocalPath.
    DWORD attributes = GetFileAttributesW(localPath.c_str());

    if (attributes == INVALID_FILE_ATTRIBUTES ||
        (attributes & FILE_ATTRIBUTE_DIRECTORY)) {

        std::wcerr << L"File does not exist: " << localPath << L"\n";
        return 1;
    }

    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

    if (FAILED(hr)) {
        PrintHr(L"CoInitializeEx", hr);
        return 1;
    }

    IAttachmentExecute* attachment = nullptr;

    hr = CoCreateInstance(
        CLSID_AttachmentServices,
        nullptr,
        CLSCTX_INPROC_SERVER,
        IID_PPV_ARGS(&attachment)
    );

    PrintHr(L"CoCreateInstance", hr);

    if (FAILED(hr)) {
        CoUninitialize();
        return 1;
    }

    // Required for Save().
    hr = attachment->SetLocalPath(localPath.c_str());
    PrintHr(L"SetLocalPath", hr);

    if (SUCCEEDED(hr)) {
        // Tell Attachment Services where the file originated.
        hr = attachment->SetSource(sourceUrl.c_str());
        PrintHr(L"SetSource", hr);
    }

    if (SUCCEEDED(hr)) {
        std::wcout << L"\nCalling IAttachmentExecute::Save()...\n";

        hr = attachment->Save();
        PrintHr(L"Save", hr);
    }

    attachment->Release();
    CoUninitialize();

    return FAILED(hr) ? 1 : 0;
}
