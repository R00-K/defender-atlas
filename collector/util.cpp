/// \file util.cpp
/// \brief Implementation of the shared helpers declared in util.h.

#include "util.h"

#include <bcrypt.h>
#include <mscat.h>
#include <softpub.h>
#include <wincrypt.h>
#include <wintrust.h>

#include <chrono>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace defenderatlas {

namespace {

/// Copy of the exception-less removal guard used while hashing files.
struct BcryptHandleGuard {
    BCRYPT_HASH_HANDLE handle = NULL;
    ~BcryptHandleGuard() {
        if (handle != NULL) {
            ::BCryptDestroyHash(handle);
        }
    }
};

constexpr DWORD kHashBufferSize = 1u << 20; // 1 MiB read chunks

} // namespace

// ---------------------------------------------------------------------------
// Text / path conversion
// ---------------------------------------------------------------------------

std::wstring from_utf8(const std::string& text) {
    if (text.empty()) {
        return std::wstring();
    }
    const int wideLength = ::MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, text.c_str(), static_cast<int>(text.size()),
        nullptr, 0);
    if (wideLength <= 0) {
        return std::wstring();
    }
    std::wstring wide(static_cast<size_t>(wideLength), L'\0');
    ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.c_str(),
                          static_cast<int>(text.size()), wide.data(), wideLength);
    return wide;
}

std::string to_utf8(const std::wstring& text) {
    if (text.empty()) {
        return std::string();
    }
    const int narrowLength = ::WideCharToMultiByte(
        CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), nullptr, 0,
        nullptr, nullptr);
    if (narrowLength <= 0) {
        return std::string();
    }
    std::string narrow(static_cast<size_t>(narrowLength), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()),
                          narrow.data(), narrowLength, nullptr, nullptr);
    return narrow;
}

// ---------------------------------------------------------------------------
// Filesystem helpers
// ---------------------------------------------------------------------------

bool path_exists(const std::filesystem::path& path) {
    std::error_code ec;
    return std::filesystem::exists(path, ec);
}

bool file_exists(const std::filesystem::path& path) {
    std::error_code ec;
    return std::filesystem::is_regular_file(path, ec);
}

void ensure_directory(const std::filesystem::path& path) {
    if (path_exists(path)) {
        return;
    }
    std::error_code ec;
    std::filesystem::create_directories(path, ec);
}

std::string read_text_file(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input.is_open()) {
        throw std::runtime_error("cannot open file for reading: " + path.string());
    }
    std::ostringstream buffer;
    buffer << input.rdbuf();
    if (input.bad()) {
        throw std::runtime_error("error while reading file: " + path.string());
    }
    return buffer.str();
}

void write_text_file(const std::filesystem::path& path, const std::string& text) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output.is_open()) {
        throw std::runtime_error("cannot open file for writing: " + path.string());
    }
    output.write(text.data(), static_cast<std::streamsize>(text.size()));
    output.flush();
    if (!output.good()) {
        throw std::runtime_error("error while writing file: " + path.string());
    }
}

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------

std::string sha256_file(const std::filesystem::path& path) {
    UniqueHandle file(::CreateFileW(
        path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!file) {
        return std::string();
    }

    BCRYPT_ALG_HANDLE algorithm = NULL;
    if (::BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr,
                                      0) != 0) {
        return std::string();
    }
    // BCryptCloseAlgorithmProvider must run exactly once per open provider.
    struct AlgorithmGuard {
        BCRYPT_ALG_HANDLE handle = NULL;
        ~AlgorithmGuard() {
            if (handle != NULL) {
                ::BCryptCloseAlgorithmProvider(handle, 0);
            }
        }
    } algorithmGuard{algorithm};

    BCRYPT_HASH_HANDLE hashHandle = NULL;
    if (::BCryptCreateHash(algorithm, &hashHandle, nullptr, 0, nullptr, 0, 0) != 0) {
        return std::string();
    }
    BcryptHandleGuard hashGuard{hashHandle};

    std::vector<unsigned char> buffer(kHashBufferSize);
    while (true) {
        DWORD bytesRead = 0;
        const BOOL ok = ::ReadFile(file.get(), buffer.data(),
                                   static_cast<DWORD>(buffer.size()), &bytesRead,
                                   nullptr);
        if (!ok) {
            return std::string();
        }
        if (bytesRead == 0) {
            break;
        }
        if (::BCryptHashData(hashHandle, buffer.data(), bytesRead, 0) != 0) {
            return std::string();
        }
    }

    unsigned char digest[32] = {};
    if (::BCryptFinishHash(hashHandle, digest, sizeof(digest), 0) != 0) {
        return std::string();
    }

    static const char* const kHex = "0123456789abcdef";
    std::string hex;
    hex.reserve(64);
    for (unsigned char byte : digest) {
        hex.push_back(kHex[(byte >> 4) & 0x0F]);
        hex.push_back(kHex[byte & 0x0F]);
    }
    return hex;
}

// ---------------------------------------------------------------------------
// Signature verification
// ---------------------------------------------------------------------------

namespace {

/// Verify an embedded Authenticode signature with WinVerifyTrust. Returns the
/// WinVerifyTrust status (0 == ERROR_SUCCESS when trusted).
LONG verify_embedded(const std::filesystem::path& path) {
    WINTRUST_FILE_INFO fileInfo = {};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = path.c_str();

    WINTRUST_DATA data = {};
    data.cbStruct = sizeof(data);
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.pFile = &fileInfo;
    data.dwStateAction = WTD_STATEACTION_VERIFY;

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    const LONG status = ::WinVerifyTrust(nullptr, &action, &data);

    data.dwStateAction = WTD_STATEACTION_CLOSE;
    ::WinVerifyTrust(nullptr, &action, &data);
    return status;
}

/// Verify that \p path is a member of a trusted Windows catalog. Many inbox
/// Microsoft binaries carry no embedded signature and are trusted purely via
/// catalog membership; WinVerifyTrust's embedded check alone reports them as
/// unsigned, so a catalog hash lookup + catalog verification is used instead.
bool verify_catalog(const std::filesystem::path& path) {
    UniqueHandle file(::CreateFileW(
        path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!file) {
        return false;
    }

    HCATADMIN admin = NULL;
    if (!::CryptCATAdminAcquireContext(&admin, nullptr, 0) || admin == NULL) {
        return false;
    }

    // RAII: release the catalog admin context when leaving this function.
    struct AdminGuard {
        HCATADMIN handle = NULL;
        ~AdminGuard() {
            if (handle != NULL) {
                ::CryptCATAdminReleaseContext(handle, 0);
            }
        }
    } adminGuard{admin};

    // Hash the file so the catalog store can be searched for a match.
    DWORD hashLength = 0;
    if (!::CryptCATAdminCalcHashFromFileHandle(file.get(), &hashLength, nullptr, 0)) {
        return false;
    }
    std::vector<unsigned char> hash(hashLength);
    if (!::CryptCATAdminCalcHashFromFileHandle(file.get(), &hashLength, hash.data(), 0)) {
        return false;
    }

    HCATINFO catalogContext =
        ::CryptCATAdminEnumCatalogFromHash(admin, hash.data(), hashLength, 0, nullptr);
    if (catalogContext == NULL) {
        return false; // not present in any trusted catalog
    }

    CATALOG_INFO catalogInfo = {};
    catalogInfo.cbStruct = sizeof(catalogInfo);
    const BOOL gotInfo = ::CryptCATCatalogInfoFromContext(catalogContext, &catalogInfo, 0);
    ::CryptCATAdminReleaseCatalogContext(admin, catalogContext, 0);
    if (!gotInfo) {
        return false;
    }

    // Verify the catalog that lists the file: trust in the file derives from
    // the catalog's own signature. The member is matched by hash, so no member
    // tag lookup is required.
    WINTRUST_CATALOG_INFO catalogData = {};
    catalogData.cbStruct = sizeof(catalogData);
    catalogData.pcwszCatalogFilePath = catalogInfo.wszCatalogFile;
    catalogData.pcwszMemberFilePath = path.c_str();
    catalogData.pbCalculatedFileHash = hash.data();
    catalogData.cbCalculatedFileHash = hashLength;
    catalogData.hCatAdmin = admin;

    WINTRUST_DATA data = {};
    data.cbStruct = sizeof(data);
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwUnionChoice = WTD_CHOICE_CATALOG;
    data.pCatalog = &catalogData;
    data.dwStateAction = WTD_STATEACTION_VERIFY;

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    const LONG status = ::WinVerifyTrust(nullptr, &action, &data);

    data.dwStateAction = WTD_STATEACTION_CLOSE;
    ::WinVerifyTrust(nullptr, &action, &data);
    return status == ERROR_SUCCESS;
}

} // namespace

bool is_signed_pe(const std::filesystem::path& path) {
    if (verify_embedded(path) == ERROR_SUCCESS) {
        return true;
    }
    return verify_catalog(path);
}

// ---------------------------------------------------------------------------
// Time
// ---------------------------------------------------------------------------

std::string utc_timestamp_iso8601() {
    SYSTEMTIME utc = {};
    ::GetSystemTime(&utc);
    char buffer[40] = {};
    std::snprintf(buffer, sizeof(buffer),
                  "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ", utc.wYear, utc.wMonth,
                  utc.wDay, utc.wHour, utc.wMinute, utc.wSecond, utc.wMilliseconds);
    return std::string(buffer);
}

// ---------------------------------------------------------------------------
// Process execution
// ---------------------------------------------------------------------------

namespace {

/// Quote \p argument for a CreateProcess command line, escaping embedded
/// quotes the way the CRT command-line parser expects.
std::wstring quote_process_argument(const std::wstring& argument) {
    std::wstring escaped;
    escaped.reserve(argument.size() + 2);
    for (std::size_t i = 0; i < argument.size(); ++i) {
        const wchar_t c = argument[i];
        if (c == L'"') {
            std::size_t backslashes = 0;
            for (std::size_t j = i; j > 0 && argument[j - 1] == L'\\'; --j) {
                ++backslashes;
            }
            escaped.append(backslashes * 2, L'\\');
            escaped += L"\\\"";
        } else {
            escaped += c;
        }
    }
    return L"\"" + escaped + L"\"";
}

constexpr DWORD kProcessHardTerminateGraceMs = 5000;

} // namespace

ProcessResult run_process(const std::filesystem::path& executable,
                          const std::vector<std::wstring>& arguments,
                          std::uint64_t timeout_ms, bool capture_output) {
    ProcessResult result;

    std::wstring command_line = quote_process_argument(executable.wstring());
    for (const std::wstring& argument : arguments) {
        command_line += L" ";
        command_line += quote_process_argument(argument);
    }

    UniqueHandle read_handle;
    UniqueHandle write_handle;
    if (capture_output) {
        SECURITY_ATTRIBUTES security = {};
        security.nLength = sizeof(security);
        security.bInheritHandle = TRUE;
        HANDLE raw_read = nullptr;
        HANDLE raw_write = nullptr;
        if (!::CreatePipe(&raw_read, &raw_write, &security, 0)) {
            result.error = last_win32_error_string();
            return result;
        }
        read_handle.reset(raw_read);
        write_handle.reset(raw_write);
        ::SetHandleInformation(read_handle.get(), HANDLE_FLAG_INHERIT, 0);
    }

    STARTUPINFOW startup = {};
    startup.cb = sizeof(startup);
    if (capture_output) {
        startup.dwFlags = STARTF_USESTDHANDLES;
        startup.hStdOutput = write_handle.get();
        startup.hStdError = write_handle.get();
        startup.hStdInput = ::GetStdHandle(STD_INPUT_HANDLE);
    }

    PROCESS_INFORMATION process_info = {};
    const BOOL created = ::CreateProcessW(
        executable.c_str(), const_cast<wchar_t*>(command_line.c_str()), nullptr,
        nullptr, TRUE, 0, nullptr, nullptr, &startup, &process_info);
    if (!created) {
        result.error = last_win32_error_string();
        return result;
    }
    result.started = true;

    UniqueHandle process_handle(process_info.hProcess);
    UniqueHandle thread_handle(process_info.hThread);

    // The parent never writes to the pipe; closing this end lets ReadFile
    // observe end-of-stream once the child exits.
    write_handle.reset();

    const DWORD wait = ::WaitForSingleObject(
        process_handle.get(), static_cast<DWORD>(timeout_ms));
    if (wait == WAIT_TIMEOUT) {
        ::TerminateProcess(process_handle.get(), 1);
        ::WaitForSingleObject(process_handle.get(), kProcessHardTerminateGraceMs);
        result.timed_out = true;
    }

    if (capture_output) {
        char buffer[2048];
        DWORD bytes_read = 0;
        while (::ReadFile(read_handle.get(), buffer, sizeof(buffer), &bytes_read,
                          nullptr) &&
               bytes_read > 0) {
            result.stdout_text.append(buffer, bytes_read);
        }
    }

    DWORD exit_code = 0;
    ::GetExitCodeProcess(process_handle.get(), &exit_code);
    result.exit_code = exit_code;
    return result;
}

// ---------------------------------------------------------------------------
// Win32 error handling
// ---------------------------------------------------------------------------

std::string win32_error_string(DWORD error_code) {
    wchar_t* message = nullptr;
    const DWORD length = ::FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, error_code, 0, reinterpret_cast<LPWSTR>(&message), 0, nullptr);
    if (length == 0 || message == nullptr) {
        return "Win32 error " + std::to_string(error_code);
    }
    std::string result = to_utf8(std::wstring(message, length));
    ::LocalFree(message);
    return result;
}

std::string last_win32_error_string() {
    return win32_error_string(::GetLastError());
}

} // namespace defenderatlas
