#pragma once
#include <cstdint>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>

namespace tx10ub::radio_handoff {
// SetChannel + four BB reads have ten existing one-second completion waits.
// Leave room for journal/IPC publication while keeping the handshake bounded.
inline constexpr std::uint64_t acknowledgement_timeout_ms=15'000;
// A private capture directory supplies the session identity. Send permits one
// round; receive can reopen discovery after an upload. Generations never repeat.
struct Request {
    unsigned generation{};
    std::uint32_t childPid{};
    unsigned from{}, to{};
    friend bool operator==(const Request&, const Request&) = default;
};
inline bool valid(const Request& request, bool receiving = false) {
    if (!request.childPid || !request.generation || (!receiving && request.generation > 2)) return false;
    return request.generation % 2 ? request.from == 6 && request.to == 44 :
        request.from == 44 && request.to == 6;
}
inline std::string encode(const Request& request) {
    return "1 "+std::to_string(request.generation)+" "+std::to_string(request.childPid)+" "+
        std::to_string(request.from)+" "+std::to_string(request.to)+"\n";
}
inline std::optional<Request> parse(std::string_view bytes, bool receiving = false) {
    if(bytes.empty()||bytes.size()>96)return std::nullopt;
    std::istringstream input{std::string(bytes)};
    unsigned version{};Request request;std::string extra;
    if(!(input>>version>>request.generation>>request.childPid>>request.from>>request.to)||
       version!=1||(input>>extra)||!valid(request, receiving))return std::nullopt;
    // Reject alternate numeric spellings, signs, trailing material and overflow.
    if(encode(request)!=bytes)return std::nullopt;
    return request;
}
inline bool admissible(const Request& request,std::uint32_t childPid,unsigned completed,
                       unsigned channel,bool handoffWaiting,bool cancelled,bool receiving = false) {
    return valid(request, receiving)&&request.childPid==childPid&&request.generation==completed+1&&
        request.from==channel&&handoffWaiting&&!cancelled;
}
inline std::string acknowledgement(const Request& request) { return encode(request)+"committed\n"; }
inline std::wstring request_name(unsigned generation) {
    return L"radio-channel-"+std::to_wstring(generation)+L".request";
}
inline std::wstring acknowledgement_name(unsigned generation) {
    return L"radio-channel-"+std::to_wstring(generation)+L".ack";
}
}
