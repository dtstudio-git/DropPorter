#pragma once

#include <windows.h>
#include <initializer_list>
#include <string>

namespace tx10ub {
inline std::wstring ReadLocalComputerName() {
    for (const auto format : {ComputerNamePhysicalDnsHostname, ComputerNamePhysicalNetBIOS}) {
        DWORD size = 0;
        if (GetComputerNameExW(format, nullptr, &size) || GetLastError() != ERROR_MORE_DATA || !size)
            continue;
        std::wstring name(size, L'\0');
        if (GetComputerNameExW(format, name.data(), &size) && size != 0) {
            name.resize(size);
            return name;
        }
    }
    return {};
}
}
