#pragma once

#include "awdl_ip_receive.h"
#include <array>
#include <optional>
#include <string_view>

namespace awdlwin::mdns {

enum class BrowseService : std::uint8_t {
    airdrop,
    app_svc_pre_pair,
    application_service_pairing
};

inline constexpr std::array<std::string_view, 3> browse_service_labels{
    "_airdrop", "_appSvcPrePair", "_applicationServicePairing"};

inline std::string_view service_label(BrowseService service) noexcept {
    const auto index = static_cast<std::size_t>(service);
    return index < browse_service_labels.size() ? browse_service_labels[index] : std::string_view{};
}

inline ip::Name service_name(BrowseService service) {
    return {std::string(service_label(service)), "_tcp", "local"};
}

inline bool equal_label(std::string_view left, std::string_view right) noexcept {
    if (left.size() != right.size()) return false;
    for (std::size_t i = 0; i < left.size(); ++i) {
        auto a = static_cast<unsigned char>(left[i]);
        auto b = static_cast<unsigned char>(right[i]);
        if (a >= 'A' && a <= 'Z') a = static_cast<unsigned char>(a + ('a' - 'A'));
        if (b >= 'A' && b <= 'Z') b = static_cast<unsigned char>(b + ('a' - 'A'));
        if (a != b) return false;
    }
    return true;
}

inline bool equal_name(const ip::Name& left, const ip::Name& right) noexcept {
    if (left.size() != right.size()) return false;
    for (std::size_t i = 0; i < left.size(); ++i)
        if (!equal_label(left[i], right[i])) return false;
    return true;
}

inline std::optional<BrowseService> service_for_name(const ip::Name& name) noexcept {
    if (name.size() != 3 || !equal_label(name[1], "_tcp") || !equal_label(name[2], "local"))
        return std::nullopt;
    for (std::size_t i = 0; i < browse_service_labels.size(); ++i)
        if (equal_label(name[0], browse_service_labels[i]))
            return static_cast<BrowseService>(i);
    return std::nullopt;
}

inline bool instance_for_service(const ip::Name& instance, BrowseService service) noexcept {
    if (instance.size() != 4 || instance.front().empty()) return false;
    const auto expected = service_name(service);
    return equal_label(instance[1], expected[0]) &&
        equal_label(instance[2], expected[1]) && equal_label(instance[3], expected[2]);
}

} // namespace awdlwin::mdns
