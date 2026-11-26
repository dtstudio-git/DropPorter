#pragma once
#include "../../src/awdl_ip_receive.h"
#include <algorithm>
#include <charconv>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace tx10ub::airdrop {
inline awdlwin::wire::Bytes discover_request(const awdlwin::ip::Address& address,std::uint16_t port,bool keepAlive=false) {
    // Binary plist empty dictionary, as OpenDrop uses without SenderRecordData.
    constexpr std::uint8_t plist[]={0x62,0x70,0x6c,0x69,0x73,0x74,0x30,0x30,0xd0,0x08,
        0,0,0,0,0,0,1,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,9};
    std::string host;
    for(std::size_t i=0;i<16;i+=2) {
        if(i)host+=':';char part[4];
        const auto n=std::to_chars(part,part+4,(unsigned(address[i])<<8)|address[i+1],16);host.append(part,n.ptr);
    }
    const auto header=std::string("POST /Discover HTTP/1.1\r\nHost: [")+host+"]:"+std::to_string(port)+
        "\r\nUser-Agent: AirDrop/1.0\r\nContent-Type: application/octet-stream\r\n"
        "Accept: */*\r\nConnection: "+(keepAlive?"keep-alive":"close")+"\r\nContent-Length: "+std::to_string(sizeof(plist))+"\r\n\r\n";
    awdlwin::wire::Bytes result(header.begin(),header.end());result.insert(result.end(),std::begin(plist),std::end(plist));return result;
}
namespace detail {
inline bool append_display_scalar(std::uint32_t value,std::string& out) {
    if(value==0||value<0x20||(value>=0x7f&&value<=0x9f)||value>0x10ffff||
       (value>=0xd800&&value<=0xdfff))return false;
    if(value<0x80)out.push_back(static_cast<char>(value));
    else if(value<0x800) {
        out.push_back(static_cast<char>(0xc0|(value>>6)));
        out.push_back(static_cast<char>(0x80|(value&0x3f)));
    } else if(value<0x10000) {
        out.push_back(static_cast<char>(0xe0|(value>>12)));
        out.push_back(static_cast<char>(0x80|((value>>6)&0x3f)));
        out.push_back(static_cast<char>(0x80|(value&0x3f)));
    } else {
        out.push_back(static_cast<char>(0xf0|(value>>18)));
        out.push_back(static_cast<char>(0x80|((value>>12)&0x3f)));
        out.push_back(static_cast<char>(0x80|((value>>6)&0x3f)));
        out.push_back(static_cast<char>(0x80|(value&0x3f)));
    }
    return out.size()<=256;
}
inline bool valid_display_utf8(std::span<const std::uint8_t> bytes,std::string& out) {
    for(std::size_t p=0;p<bytes.size();) {
        const auto first=bytes[p++];std::uint32_t value=0;unsigned continuation=0;
        if(first<0x80)value=first;
        else if(first>=0xc2&&first<=0xdf){value=first&0x1f;continuation=1;}
        else if(first>=0xe0&&first<=0xef){value=first&0x0f;continuation=2;}
        else if(first>=0xf0&&first<=0xf4){value=first&0x07;continuation=3;}
        else return false;
        if(continuation>bytes.size()-p)return false;
        for(unsigned i=0;i<continuation;++i) {
            const auto next=bytes[p++];if((next&0xc0)!=0x80)return false;
            value=(value<<6)|(next&0x3f);
        }
        if((continuation==1&&value<0x80)||(continuation==2&&value<0x800)||
           (continuation==3&&value<0x10000)||!append_display_scalar(value,out))return false;
    }
    return !out.empty();
}
} // namespace detail

// Read the receiver's advertised display name from the binary plist returned
// by OpenDrop-compatible POST /Discover. Unknown plist values remain opaque.
inline std::optional<std::string> receiver_computer_name(std::span<const std::uint8_t> bytes) {
    if(bytes.size()<40||std::string_view(reinterpret_cast<const char*>(bytes.data()),8)!="bplist00")
        return std::nullopt;
    const auto trailer=bytes.size()-32;
    const auto read_number=[&](std::size_t at,unsigned width,std::uint64_t& value) {
        if(!width||width>8||at>bytes.size()||width>bytes.size()-at)return false;
        value=0;for(unsigned i=0;i<width;++i)value=(value<<8)|bytes[at+i];return true;
    };
    const auto offsetWidth=bytes[trailer+6],refWidth=bytes[trailer+7];
    std::uint64_t objectCount64=0,top=0,table64=0;
    if(!read_number(trailer+8,8,objectCount64)||!read_number(trailer+16,8,top)||
       !read_number(trailer+24,8,table64)||!offsetWidth||offsetWidth>8||!refWidth||refWidth>8||
       !objectCount64||objectCount64>256||top>=objectCount64||table64>trailer||table64<8)
        return std::nullopt;
    const auto objectCount=static_cast<std::size_t>(objectCount64);
    const auto table=static_cast<std::size_t>(table64);
    if(objectCount>(trailer-table)/offsetWidth||table+objectCount*offsetWidth!=trailer)
        return std::nullopt;
    const auto object_offset=[&](std::uint64_t ref,std::size_t& offset) {
        if(ref>=objectCount)return false;
        std::uint64_t value=0;
        if(!read_number(table+static_cast<std::size_t>(ref)*offsetWidth,offsetWidth,value)||value<8||value>=table)
            return false;
        offset=static_cast<std::size_t>(value);return true;
    };
    const auto read_length=[&](std::size_t& cursor,std::uint8_t info,std::uint64_t& length) {
        if(info<15){length=info;return true;}
        if(cursor>=table)return false;
        const auto marker=bytes[cursor++];if((marker>>4)!=1||(marker&0x0f)>3)return false;
        const unsigned width=1u<<(marker&0x0f);
        if(cursor>table||width>table-cursor||!read_number(cursor,width,length))return false;
        cursor+=width;return true;
    };
    const auto read_string=[&](std::uint64_t ref,std::string& output) {
        std::size_t offset=0;if(!object_offset(ref,offset))return false;
        std::size_t cursor=offset;const auto marker=bytes[cursor++];
        const auto kind=marker>>4;std::uint64_t length=0;
        if(cursor>table||(kind!=5&&kind!=6&&kind!=7)||
           !read_length(cursor,marker&0x0f,length)||length>256||cursor>table)return false;
        output.clear();
        if(kind==5) {
            if(length>table-cursor)return false;
            if(std::any_of(bytes.begin()+cursor,bytes.begin()+cursor+static_cast<std::size_t>(length),
                           [](std::uint8_t c){return c>0x7f;}))return false;
            return detail::valid_display_utf8(bytes.subspan(cursor,static_cast<std::size_t>(length)),output);
        }
        if(kind==7) {
            if(length>table-cursor)return false;
            return detail::valid_display_utf8(bytes.subspan(cursor,static_cast<std::size_t>(length)),output);
        }
        if(length>(table-cursor)/2)return false;
        for(std::size_t i=0;i<length;++i) {
            const auto at=cursor+i*2;
            std::uint32_t value=(std::uint32_t(bytes[at])<<8)|bytes[at+1];
            if(value>=0xd800&&value<=0xdbff) {
                if(i+1>=length)return false;
                const auto nextAt=at+2;
                const auto low=(std::uint32_t(bytes[nextAt])<<8)|bytes[nextAt+1];
                if(low<0xdc00||low>0xdfff)return false;
                value=0x10000+((value-0xd800)<<10)+(low-0xdc00);++i;
            } else if(value>=0xdc00&&value<=0xdfff)return false;
            if(!detail::append_display_scalar(value,output))return false;
        }
        return !output.empty();
    };
    std::size_t root=0;if(!object_offset(top,root))return std::nullopt;
    std::size_t cursor=root;const auto marker=bytes[cursor++];std::uint64_t count=0;
    if((marker>>4)!=13||!read_length(cursor,marker&0x0f,count)||count>256||
       count>(table-cursor)/(2*refWidth))return std::nullopt;
    std::optional<std::string> result;bool sawName=false;
    for(std::size_t i=0;i<count;++i) {
        std::uint64_t keyRef=0,valueRef=0;std::string key;
        if(!read_number(cursor+i*refWidth,refWidth,keyRef)||
           !read_number(cursor+(count+i)*refWidth,refWidth,valueRef)||!read_string(keyRef,key))return std::nullopt;
        if(key!="ReceiverComputerName")continue;
        if(sawName)return std::nullopt;
        sawName=true;std::string value;if(!read_string(valueRef,value))return std::nullopt;
        result=std::move(value);
    }
    return result;
}

// Bounded single response; accepts Content-Length, chunked, or clean EOF.
// Encodings and ambiguous framing are rejected, never guessed.
class Response {
    static constexpr std::size_t headerLimit=16384,bodyLimit=65536,wireLimit=131072;
    std::string wire_;
    awdlwin::wire::Bytes body_;
    std::size_t bodyStart_=0,length_=0;
    bool headers_=false,hasLength_=false,chunked_=false,done_=false,failed_=false;
    unsigned status_=0;
    static std::string lower(std::string_view v) {
        std::string s(v);for(auto& c:s)if(c>='A'&&c<='Z')c=static_cast<char>(c+'a'-'A');return s;
    }
    static std::string_view trim(std::string_view v) {
        while(!v.empty()&&(v.front()==' '||v.front()=='\t'))v.remove_prefix(1);
        while(!v.empty()&&(v.back()==' '||v.back()=='\t'))v.remove_suffix(1);return v;
    }
    bool parse() {
        if(!headers_) {
            const auto end=wire_.find("\r\n\r\n");
            if(end==std::string::npos)return wire_.size()<=headerLimit;
            if(end>headerLimit)return false;
            const auto first=wire_.find("\r\n");
            if(first<13||wire_[12]!=' '||(wire_.compare(0,9,"HTTP/1.1 ")&&wire_.compare(0,9,"HTTP/1.0 ")))return false;
            const auto code=std::string_view(wire_).substr(9,3);
            if(code.find_first_not_of("0123456789")!=std::string::npos)return false;
            const auto converted=std::from_chars(code.data(),code.data()+code.size(),status_);
            if(converted.ec!=std::errc{}||status_<200||status_>599)return false;
            bool transferSeen=false,encodingSeen=false;
            for(auto p=first+2;p<end;) {
                const auto lineEnd=wire_.find("\r\n",p);const auto line=std::string_view(wire_).substr(p,lineEnd-p);
                const auto colon=line.find(':');if(colon==std::string_view::npos||colon==0||line.front()==' '||line.front()=='\t')return false;
                const auto key=lower(line.substr(0,colon));const auto value=trim(line.substr(colon+1));
                if(key=="content-length") {
                    if(hasLength_||value.empty())return false;
                    const auto n=std::from_chars(value.data(),value.data()+value.size(),length_);
                    if(n.ec!=std::errc{}||n.ptr!=value.data()+value.size()||length_>bodyLimit)return false;
                    hasLength_=true;
                } else if(key=="transfer-encoding") {
                    if(transferSeen||lower(value)!="chunked")return false;transferSeen=chunked_=true;
                } else if(key=="content-encoding") {
                    if(encodingSeen||lower(value)!="identity")return false;encodingSeen=true;
                }
                p=lineEnd+2;
            }
            if(hasLength_&&chunked_)return false;
            headers_=true;bodyStart_=end+4;
        }
        if(hasLength_) {
            if(wire_.size()-bodyStart_>length_)return false;
            if(wire_.size()-bodyStart_==length_){body_.assign(wire_.begin()+bodyStart_,wire_.end());done_=true;}
        } else if(chunked_) {
            awdlwin::wire::Bytes decoded;auto p=bodyStart_;
            for(;;) {
                const auto e=wire_.find("\r\n",p);if(e==std::string::npos)return wire_.size()-p<=1024;
                auto sizeText=std::string_view(wire_).substr(p,e-p);sizeText=sizeText.substr(0,sizeText.find(';'));
                std::size_t size=0;const auto n=std::from_chars(sizeText.data(),sizeText.data()+sizeText.size(),size,16);
                if(sizeText.empty()||n.ec!=std::errc{}||n.ptr!=sizeText.data()+sizeText.size()||size>bodyLimit-decoded.size())return false;
                p=e+2;
                if(size==0) {
                    if(wire_.size()-p<2)return true;
                    if(wire_.compare(p,2,"\r\n")!=0)return false; // No trailers needed by this endpoint.
                    if(p+2!=wire_.size())return false;
                    body_=std::move(decoded);done_=true;break;
                }
                if(wire_.size()-p<size+2)return true;
                decoded.insert(decoded.end(),wire_.begin()+p,wire_.begin()+p+size);p+=size;
                if(wire_.compare(p,2,"\r\n")!=0)return false;p+=2;
            }
        } else if(wire_.size()-bodyStart_>bodyLimit)return false;
        return true;
    }
public:
    bool feed(std::span<const std::uint8_t> b) {
        if(failed_||done_||b.size()>wireLimit-wire_.size()){failed_=true;return false;}
        wire_.append(reinterpret_cast<const char*>(b.data()),b.size());if(!parse())failed_=true;return !failed_;
    }
    bool finish() {
        if(!failed_&&headers_&&!hasLength_&&!chunked_&&!done_){body_.assign(wire_.begin()+bodyStart_,wire_.end());done_=true;}
        if(!done_)failed_=true;return !failed_;
    }
    bool complete()const{return done_&&!failed_;}
    unsigned status()const{return status_;}
    const awdlwin::wire::Bytes& body()const{return body_;}
};
} // namespace tx10ub::airdrop
