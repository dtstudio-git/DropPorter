#pragma once
// Wire contract between the WPF bridge (unelevated owner) and the elevated
// "DropPorterRuntime.exe --broker <ownerPid> <token>" process. The broker starts the
// runtime for "--request <path>" on behalf of its owner, so UAC is asked once per
// app run instead of once per transfer. The runtime still validates every request.
#include <windows.h>
#include <string>

namespace dropporter::broker {
constexpr DWORD kRequestMagic = 0x31424444;  // "DDB1"
constexpr DWORD kReplyMagic = 0x32424444;    // "DDB2"
constexpr DWORD kMaxParameterChars = 32767;
constexpr DWORD kConnectTimeoutMs = 30000;
constexpr DWORD kReplyTimeoutMs = 30000;

// Request message: header followed by parameterChars UTF-16 code units (no terminator).
struct RequestHeader {
    DWORD magic;
    DWORD parameterChars;
};
// Reply message. process is a handle value valid in the owner process
// (SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION), or 0 with error set.
struct Reply {
    DWORD magic;
    DWORD error;
    ULONGLONG process;
};

inline std::wstring PipeName(const std::wstring& token) { return L"\\\\.\\pipe\\DropPorter-broker-" + token; }

inline bool IsToken(const std::wstring& token) {
    if (token.size() != 32) return false;
    for (const wchar_t ch : token) if (!((ch >= L'0' && ch <= L'9') || (ch >= L'a' && ch <= L'f'))) return false;
    return true;
}
}
