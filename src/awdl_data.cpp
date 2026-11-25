#include "awdl_data.h"

#include <algorithm>

namespace awdlwin::wire {
namespace {
constexpr std::array<std::uint8_t, 8> apple_snap{0xaa,0xaa,3,0,0x17,0xf2,8,0};
constexpr MacAddress awdl_bssid{0,0x25,0,0xff,0x94,0x73};
constexpr std::size_t max_mpdu_size = 65535;
constexpr std::size_t max_msdus = 64;

std::uint16_t le16(std::span<const std::uint8_t> b, std::size_t at) {
    return static_cast<std::uint16_t>(b[at] | (b[at+1] << 8));
}
std::uint16_t be16(std::span<const std::uint8_t> b, std::size_t at) {
    return static_cast<std::uint16_t>((b[at] << 8) | b[at+1]);
}
MacAddress mac(std::span<const std::uint8_t> b, std::size_t at) {
    MacAddress result{};
    std::copy_n(b.begin()+at, result.size(), result.begin());
    return result;
}
bool nonzero(const MacAddress& value) {
    return std::any_of(value.begin(), value.end(), [](auto b){return b != 0;});
}
bool snap(std::span<const std::uint8_t> b) {
    return b.size() >= apple_snap.size() &&
        std::equal(apple_snap.begin(), apple_snap.end(), b.begin());
}
CodecResult<DataMsdu> msdu(std::span<const std::uint8_t> body,
                           const MacAddress& destination, const MacAddress& source) {
    if (body.size() < 16) return CodecResult<DataMsdu>::failure(CodecError::truncated);
    if (!snap(body)) return CodecResult<DataMsdu>::failure(CodecError::not_awdl);
    if (le16(body,8) != 0x0403 || le16(body,12) != 0 ||
        !nonzero(source) || (source[0]&1) || !nonzero(destination))
        return CodecResult<DataMsdu>::failure(CodecError::malformed_data);
    return CodecResult<DataMsdu>::success({destination,source,le16(body,10),
        be16(body,14),Bytes(body.begin()+16,body.end())});
}
} // namespace

CodecResult<Bytes> build_awdl_data_mpdu(const DataMsdu& value,std::uint16_t sequence) {
    using Result=CodecResult<Bytes>;
    if(!nonzero(value.source)||(value.source[0]&1)||!nonzero(value.destination)||sequence>4095)
        return Result::failure(CodecError::malformed_data);
    if(value.payload.size()>max_mpdu_size-40)return Result::failure(CodecError::size_limit);
    Bytes bytes(24,0);bytes[0]=8;
    std::copy(value.destination.begin(),value.destination.end(),bytes.begin()+4);
    std::copy(value.source.begin(),value.source.end(),bytes.begin()+10);
    std::copy(awdl_bssid.begin(),awdl_bssid.end(),bytes.begin()+16);
    bytes[22]=static_cast<std::uint8_t>(sequence<<4);bytes[23]=static_cast<std::uint8_t>(sequence>>4);
    bytes.insert(bytes.end(),apple_snap.begin(),apple_snap.end());
    bytes.insert(bytes.end(),{3,4,static_cast<std::uint8_t>(value.awdl_sequence),
        static_cast<std::uint8_t>(value.awdl_sequence>>8),0,0,
        static_cast<std::uint8_t>(value.ether_type>>8),static_cast<std::uint8_t>(value.ether_type)});
    bytes.insert(bytes.end(),value.payload.begin(),value.payload.end());
    return Result::success(std::move(bytes));
}

bool is_awdl_data_candidate(std::span<const std::uint8_t> mpdu) {
    if (mpdu.size() < 24) return false;
    const auto subtype = mpdu[0] & 0xfc;
    if (subtype != 8 && subtype != 0x88) return false;
    if (std::equal(awdl_bssid.begin(),awdl_bssid.end(),mpdu.begin()+16)) return true;
    std::size_t offset = 24;
    if (subtype == 0x88) {
        if (mpdu.size() < 26) return false;
        offset += 2;
        if (le16(mpdu,24)&0x80) offset += 14;
    }
    return offset <= mpdu.size() && snap(mpdu.subspan(offset));
}

CodecResult<DataMpdu> parse_awdl_data_mpdu(std::span<const std::uint8_t> input,
                                         bool has_fcs) {
    using Result = CodecResult<DataMpdu>;
    if (input.size() > max_mpdu_size) return Result::failure(CodecError::size_limit);
    if (input.size() < 24+(has_fcs?4u:0u)) return Result::failure(CodecError::truncated);
    const auto b = input.first(input.size()-(has_fcs?4:0));
    const auto fc = le16(b,0);
    const auto subtype = fc & 0xfc;
    if (subtype != 8 && subtype != 0x88) return Result::failure(CodecError::not_awdl);
    const auto sequence = le16(b,22);
    if ((fc & (0x0003|0x0300|0x0400|0x4000|0x8000)) != 0 || (sequence&15) != 0)
        return Result::failure(CodecError::unsupported_mac_header);
    const bool qos = subtype == 0x88;
    const std::size_t header_size = qos?26:24;
    if (b.size() < header_size) return Result::failure(CodecError::truncated);
    const bool aggregated = qos && (le16(b,24)&0x80) != 0;
    DataMpdu result{mac(b,4),mac(b,10),mac(b,16),
        static_cast<std::uint16_t>(sequence>>4),(fc&0x0800)!=0,qos,aggregated,{}};
    if (!nonzero(result.source) || (result.source[0]&1) || !nonzero(result.destination))
        return Result::failure(CodecError::malformed_data);
    auto payload = b.subspan(header_size);
    if (!aggregated) {
        auto decoded = msdu(payload,result.destination,result.source);
        if (!decoded) return Result::failure(decoded.error(),header_size+decoded.offset());
        result.msdus.push_back(std::move(decoded.value()));
    } else {
        std::size_t cursor = 0;
        while (cursor < payload.size()) {
            if (result.msdus.size() >= max_msdus) return Result::failure(CodecError::size_limit);
            if (payload.size()-cursor < 14) return Result::failure(CodecError::truncated,header_size+cursor);
            const auto sub = payload.subspan(cursor);
            const auto length = be16(sub,12);
            if (length > sub.size()-14) return Result::failure(CodecError::truncated,header_size+cursor+14);
            auto decoded = msdu(sub.subspan(14,length),mac(sub,0),mac(sub,6));
            if (!decoded) return Result::failure(decoded.error(),header_size+cursor+14+decoded.offset());
            result.msdus.push_back(std::move(decoded.value()));
            const auto consumed = 14+static_cast<std::size_t>(length);
            cursor += consumed;
            if (cursor == payload.size()) break;
            const auto padding = (4-consumed%4)%4;
            if (payload.size()-cursor < padding+14)
                return Result::failure(CodecError::truncated,header_size+cursor);
            cursor += padding;
        }
        if (result.msdus.empty()) return Result::failure(CodecError::truncated,header_size);
    }
    return Result::success(std::move(result));
}
} // namespace awdlwin::wire
