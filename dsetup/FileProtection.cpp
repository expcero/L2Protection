#include "FileProtection.h"
#include <windows.h>
#include <wincrypt.h>
#include <fstream>

#pragma comment(lib, "Advapi32.lib")

static const wchar_t* FILE_INTERFACE_U = L"interface.u";
static const wchar_t* FILE_INTERFACE_DAT = L"interface.xdat";

// SHA-256 of the interface in C:/game/l2/system, verified 2026-10-26.
// Keep integrity checks enabled for the matching local test client.
static const char HASH_INTERFACE_U[] = "4ca40e2936138d9551412767c695b6e54e8f2843daf437536811705704b91019";
static const char HASH_INTERFACE_DAT[] = "ee755d9865e548398d822493b9536a40b3f7483108b582723d89b03eeb803c55";
static_assert(sizeof(HASH_INTERFACE_U) == 65, "interface.u SHA-256 must contain 64 characters");
static_assert(sizeof(HASH_INTERFACE_DAT) == 65, "interface.xdat SHA-256 must contain 64 characters");

void ProtectionLog(const char* event);

static std::wstring ProtectedPath(const wchar_t* name)
{
    HMODULE module = NULL;
    wchar_t path[MAX_PATH] = {};
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCWSTR>(&ProtectedPath), &module)) return L"";
    DWORD length = GetModuleFileNameW(module, path, MAX_PATH);
    if (!length || length >= MAX_PATH) return L"";
    std::wstring full(path);
    auto slash = full.find_last_of(L"\\/");
    if (slash == std::wstring::npos) return L"";
    return full.substr(0, slash + 1) + name;
}

bool GetFileHash(const wchar_t* file, std::string& outHash)
{
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        return false;

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
        return false;

    std::ifstream f(file, std::ios::binary);
    if (!f.is_open())
        return false;

    char buffer[4096];

    while (f.read(buffer, sizeof(buffer)) || f.gcount())
    {
        DWORD bytesRead = (DWORD)f.gcount();
        CryptHashData(hHash, (BYTE*)buffer, bytesRead, 0);
    }

    BYTE hash[32];
    DWORD len = 32;

    if (!CryptGetHashParam(hHash, HP_HASHVAL, hash, &len, 0))
        return false;

    char hex[65] = { 0 };
    for (int i = 0; i < 32; i++)
        sprintf_s(hex + i * 2, 3, "%02X", hash[i]);

    outHash = hex;

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    return true;
}

FileCheckResult VerifyProtectedFiles()
{
    FileCheckResult result = {};
    result.allOk = true;

    std::string hash;

    // =====================
    // interface.u
    // =====================
    if (!GetFileHash(ProtectedPath(FILE_INTERFACE_U).c_str(), hash))
    {
        ProtectionLog("files: interface.u missing or unreadable");
        result.allOk = false;
        result.fileMissing = true;
        result.fileName = FILE_INTERFACE_U;
        return result;
    }

    if (_stricmp(hash.c_str(), HASH_INTERFACE_U) != 0)
    {
        ProtectionLog("files: interface.u SHA-256 mismatch");
        result.allOk = false;
        result.fileChanged = true;
        result.fileName = FILE_INTERFACE_U;
        result.hash = hash;
        return result;
    }

    // =====================
    // interface.dat
    // =====================
    if (!GetFileHash(ProtectedPath(FILE_INTERFACE_DAT).c_str(), hash))
    {
        ProtectionLog("files: interface.xdat missing or unreadable");
        result.allOk = false;
        result.fileMissing = true;
        result.fileName = FILE_INTERFACE_DAT;
        return result;
    }

    if (_stricmp(hash.c_str(), HASH_INTERFACE_DAT) != 0)
    {
        ProtectionLog("files: interface.xdat SHA-256 mismatch");
        result.allOk = false;
        result.fileChanged = true;
        result.fileName = FILE_INTERFACE_DAT;
        result.hash = hash;
        return result;
    }

    ProtectionLog("files: interface integrity OK");
    return result;
}
