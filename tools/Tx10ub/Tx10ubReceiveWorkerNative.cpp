#include <Windows.h>
#include <objbase.h>
#include "Tx10ubComputerName.h"
#include "../DropPorter/DropPorterSessionMarkers.h"
#include "../DropPorter/DropPorterReceiveOffer.h"
#include "Tx10ubReceiveState.h"
#include "Tx10ubReceiveWorkerProtocol.h"
#include "Tx10ubUserFileAccess.h"
#include <zlib.h>
#include <algorithm>
#include <array>
#include <bit>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdio>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <typeinfo>
#include <utility>
#include <variant>
#include <vector>
#include <utility>

namespace {
namespace receive_state = tx10ub::receive_state;
namespace markers = dropporter::session_markers;
namespace offer = dropporter::receive_offer;
using receive_state::FailureReason;
using receive_state::Phase;

std::string state_field(const char* name) {
  return std::string(",\"") + name + "\":";
}
using Bytes=std::vector<std::uint8_t>;
using Clock=std::chrono::steady_clock;
constexpr auto ReceiveIdleTimeout = std::chrono::minutes(10);
constexpr std::uint8_t Open=1,Data=2,Close=3,Tick=4;
using tx10ub::receive_worker_protocol::MaxConnections;
constexpr std::size_t MaxFrame=tx10ub::receive_worker_protocol::MaxFrameBytes,MaxHeaders=16*1024,MaxMetadata=64*1024,MaxExpandedPlistBytes=4*1024*1024;
// Ask may include a binary FileIcon; control files and Discover remain smaller.
constexpr std::size_t MaxAskBody=1024*1024;
constexpr std::uint64_t MaxFileBytes=(std::uint64_t{1}<<33)-1,MaxArchiveBytes=MaxFileBytes+16*1024*1024;
constexpr std::size_t MaxCpioName=4096,MaxCpioTrailingZeroes=64*1024,MaxHttpChunkLine=128,MaxHttpTrailers=8192;
constexpr auto AskTimeout=std::chrono::seconds(55),UploadTimeout=std::chrono::seconds(120),QuietFinish=std::chrono::seconds(3);
constexpr auto UploadWaitingNotice = std::chrono::seconds(5);
constexpr auto UploadStallTimeout = std::chrono::seconds(30);
constexpr auto SizedUploadEndGrace=std::chrono::milliseconds(500);
constexpr auto StateWriteInterval=std::chrono::milliseconds(250);
constexpr std::size_t CopyChunk=64*1024;
constexpr std::uint32_t DvzipBlockLimit=2*1024*1024,DvzipOutputBlockLimit=1024*1024;
struct ProtocolError:std::runtime_error{using runtime_error::runtime_error;};
struct TooLarge:ProtocolError{using ProtocolError::ProtocolError;};
struct Cancelled:std::runtime_error{using runtime_error::runtime_error;};
struct NativeError:std::runtime_error{
 using runtime_error::runtime_error;
 NativeError(std::string message,FailureReason failure):runtime_error(std::move(message)),reason(failure){}
 FailureReason reason=FailureReason::Other;
};
struct NotFound:std::runtime_error{using runtime_error::runtime_error;};

std::wstring utf8_wide(std::string_view s){
 if(s.empty())return{};int n=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s.data(),static_cast<int>(s.size()),nullptr,0);
 if(!n)throw ProtocolError("invalid UTF-8 text");std::wstring out(static_cast<std::size_t>(n),L'\0');
 if(MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s.data(),static_cast<int>(s.size()),out.data(),n)!=n)throw ProtocolError("invalid UTF-8 text");return out;
}
std::string wide_utf8(std::wstring_view s){
 if(s.empty())return{};int n=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,s.data(),static_cast<int>(s.size()),nullptr,0,nullptr,nullptr);
 if(!n)throw ProtocolError("invalid Unicode text");std::string out(static_cast<std::size_t>(n),'\0');
 if(WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,s.data(),static_cast<int>(s.size()),out.data(),n,nullptr,nullptr)!=n)throw ProtocolError("invalid Unicode text");return out;
}
std::wstring normalize_nfc(std::wstring_view s){
 int n=NormalizeString(NormalizationC,s.data(),static_cast<int>(s.size()),nullptr,0);if(n<=0)throw ProtocolError("filename normalization failed");
 std::wstring out(static_cast<std::size_t>(n),L'\0');n=NormalizeString(NormalizationC,s.data(),static_cast<int>(s.size()),out.data(),n);
 if(n<=0)throw ProtocolError("filename normalization failed");out.resize(static_cast<std::size_t>(n));return out;
}
std::wstring invariant_lower(std::wstring_view s){
 if(s.empty())return{};int n=LCMapStringEx(LOCALE_NAME_INVARIANT,LCMAP_LOWERCASE,s.data(),static_cast<int>(s.size()),nullptr,0,nullptr,nullptr,0);
 if(n<=0)throw ProtocolError("filename case normalization failed");std::wstring out(static_cast<std::size_t>(n),L'\0');
 n=LCMapStringEx(LOCALE_NAME_INVARIANT,LCMAP_LOWERCASE,s.data(),static_cast<int>(s.size()),out.data(),n,nullptr,nullptr,0);
 if(n<=0)throw ProtocolError("filename case normalization failed");out.resize(static_cast<std::size_t>(n));return out;
}
bool control_char(wchar_t c){WORD type=0;GetStringTypeW(CT_CTYPE1,&c,1,&type);return (type&C1_CNTRL)!=0;}
bool format_char(wchar_t c){
 return c==0x00ad||(c>=0x0600&&c<=0x0605)||c==0x061c||c==0x06dd||c==0x070f||
        c==0x08e2||c==0x180e||(c>=0x200b&&c<=0x200f)||(c>=0x202a&&c<=0x202e)||
        (c>=0x2060&&c<=0x206f)||c==0xfeff||(c>=0xfff9&&c<=0xfffb)||
        (c>=0x1bca0&&c<=0x1bca3)||(c>=0x1d173&&c<=0x1d17a);
}
bool whitespace(wchar_t c){
 return c==L' '||(c>=L'\t'&&c<=L'\r')||c==0x0085||c==0x00a0||c==0x1680||
        (c>=0x2000&&c<=0x200a)||c==0x2028||c==0x2029||c==0x202f||c==0x205f||c==0x3000;
}
std::string safe_display(std::string_view text,std::size_t limit=256){
 std::wstring in;try{in=utf8_wide(text);}catch(...){in=L"nearby device";}
 std::wstring out;bool space=false;
 for(wchar_t c:in){if(control_char(c)||format_char(c)||whitespace(c)){space=!out.empty();continue;}if(space&&!out.empty())out.push_back(L' ');space=false;if(out.size()<limit)out.push_back(c);}
 while(!out.empty()&&out.back()==L' ')out.pop_back();if(out.empty())out=L"nearby device";return wide_utf8(out);
}
std::string safe_filename(std::string_view text){
 const auto in=normalize_nfc(utf8_wide(text));std::wstring name;
 for(wchar_t c:in)name.push_back((c==L'<'||c==L'>'||c==L':'||c==L'"'||c==L'/'||c==L'\\'||c==L'|'||c==L'?'||c==L'*'||control_char(c)||format_char(c))?L'_':c);
 while(!name.empty()&&name.front()==L' ')name.erase(name.begin());while(!name.empty()&&(name.back()==L' '||name.back()==L'.'))name.pop_back();
 if(name.empty()||name==L"."||name==L"..")name=L"received-file";
 const auto dot=name.find(L'.');auto stem=invariant_lower(name.substr(0,dot));
 static const std::set<std::wstring> reserved=[](){std::set<std::wstring> r{L"con",L"prn",L"aux",L"nul",L"com¹",L"com²",L"com³",L"lpt¹",L"lpt²",L"lpt³"};for(int i=1;i<=9;++i){r.insert(L"com"+std::to_wstring(i));r.insert(L"lpt"+std::to_wstring(i));}return r;}();
 if(reserved.contains(stem))name.insert(name.begin(),L'_');
 std::wstring bounded;for(std::size_t i=0;i<name.size();++i){if(bounded.size()>=240)break;if(name[i]>=0xd800&&name[i]<=0xdbff){if(i+1>=name.size()||name[i+1]<0xdc00||name[i+1]>0xdfff)throw ProtocolError("filename has invalid Unicode");if(bounded.size()+2>240)break;bounded.push_back(name[i]);bounded.push_back(name[++i]);}else if(name[i]>=0xdc00&&name[i]<=0xdfff)throw ProtocolError("filename has invalid Unicode");else bounded.push_back(name[i]);}
 while(!bounded.empty()&&(bounded.back()==L' '||bounded.back()==L'.'))bounded.pop_back();if(bounded.empty())bounded=L"received-file";return wide_utf8(bounded);
}
bool archive_component(std::string_view name) {
  return !name.empty() && name != "." && name != ".." &&
         name.find_first_of("/\\") == std::string_view::npos &&
         name.find('\0') == std::string_view::npos;
}
std::string archive_folder(std::string_view name) {
  if (!archive_component(name))
    throw ProtocolError("invalid archive wrapper directory");
  const auto normalized = wide_utf8(normalize_nfc(utf8_wide(name)));
  if (safe_filename(name) != normalized)
    throw ProtocolError("invalid archive wrapper directory");
  return normalized;
}
struct ArchivePath { std::string folder, name; };
ArchivePath archive_path(std::string_view raw) {
  if (raw.starts_with("./"))
    raw.remove_prefix(2);
  const auto slash = raw.find('/');
  const auto leaf = slash == std::string_view::npos ? raw : raw.substr(slash + 1);
  if (!archive_component(leaf))
    throw ProtocolError("invalid archive file path");
  return {slash == std::string_view::npos ? std::string{} : archive_folder(raw.substr(0, slash)),
          safe_filename(leaf)};
}
std::string unique_name(std::string_view original,std::set<std::wstring>& used){
 const auto wide=utf8_wide(original);const auto dot=wide.find_last_of(L'.');const bool hasExtension=dot!=std::wstring::npos&&dot!=0;const auto stem=hasExtension?wide.substr(0,dot):wide;const auto ext=hasExtension?wide.substr(dot):std::wstring{};auto candidate=wide;unsigned suffix=2;
 while(used.contains(invariant_lower(candidate))){const auto marker=L" ("+std::to_wstring(suffix++)+L")";const auto limit=240-marker.size()-ext.size();std::wstring part;for(auto c:stem){if(part.size()>=limit)break;part.push_back(c);}while(!part.empty()&&(part.back()==L' '||part.back()==L'.'))part.pop_back();candidate=(part.empty()?L"received-file":part)+marker+ext;}
 used.insert(invariant_lower(candidate));return wide_utf8(candidate);
}
std::string json_escape(std::string_view s){
 static constexpr char h[]="0123456789abcdef";std::string out="\"";
 for(unsigned char c:s){if(c=='"'||c=='\\'){out.push_back('\\');out.push_back(static_cast<char>(c));}else if(c<0x20){out+="\\u00";out.push_back(h[c>>4]);out.push_back(h[c&15]);}else out.push_back(static_cast<char>(c));}out.push_back('"');return out;
}
std::uint64_t parse_uint(std::string_view s,std::uint64_t max,std::string_view label){
 if(s.empty()||s.size()>20||std::any_of(s.begin(),s.end(),[](unsigned char c){return c<'0'||c>'9';}))throw ProtocolError("invalid "+std::string(label));
 std::uint64_t v=0;const auto r=std::from_chars(s.data(),s.data()+s.size(),v);if(r.ec!=std::errc{}||r.ptr!=s.data()+s.size())throw ProtocolError("invalid "+std::string(label));if(v>max)throw TooLarge(std::string(label)+" exceeds limit");return v;
}
std::string lower_ascii(std::string_view s){std::string r(s);for(auto& c:r)if(c>='A'&&c<='Z')c=static_cast<char>(c+32);return r;}
std::string_view trim_ows(std::string_view s){while(!s.empty()&&(s.front()==' '||s.front()=='\t'))s.remove_prefix(1);while(!s.empty()&&(s.back()==' '||s.back()=='\t'))s.remove_suffix(1);return s;}

struct JsonValue{using Array=std::vector<JsonValue>;using Object=std::map<std::string,JsonValue,std::less<>>;std::variant<std::nullptr_t,bool,std::uint64_t,std::string,Array,Object> value;};
class JsonParser{
 std::string_view s_;std::size_t p_=0;
 void ws(){while(p_<s_.size()&&(s_[p_]==' '||s_[p_]=='\t'||s_[p_]=='\r'||s_[p_]=='\n'))++p_;}
 char take(){if(p_>=s_.size())throw ProtocolError("invalid JSON");return s_[p_++];}
 std::uint32_t hex4(){std::uint32_t n=0;for(int i=0;i<4;++i){auto c=take();n<<=4;if(c>='0'&&c<='9')n|=c-'0';else if(c>='a'&&c<='f')n|=c-'a'+10;else if(c>='A'&&c<='F')n|=c-'A'+10;else throw ProtocolError("invalid JSON escape");}return n;}
 std::string string(){
  if(take()!='"')throw ProtocolError("invalid JSON string");std::wstring wide;std::string raw;
  while(p_<s_.size()){auto c=static_cast<unsigned char>(take());if(c=='"'){wide+=utf8_wide(raw);return wide_utf8(wide);}if(c=='\\'){wide+=utf8_wide(raw);raw.clear();auto e=take();if(e=='"'||e=='\\'||e=='/')wide.push_back(static_cast<wchar_t>(e));else if(e=='b')wide.push_back(L'\b');else if(e=='f')wide.push_back(L'\f');else if(e=='n')wide.push_back(L'\n');else if(e=='r')wide.push_back(L'\r');else if(e=='t')wide.push_back(L'\t');else if(e=='u'){auto cp=hex4();if(cp>=0xd800&&cp<=0xdbff){if(take()!='\\'||take()!='u')throw ProtocolError("invalid JSON surrogate");auto low=hex4();if(low<0xdc00||low>0xdfff)throw ProtocolError("invalid JSON surrogate");cp=0x10000+((cp-0xd800)<<10)+(low-0xdc00);}else if(cp>=0xdc00&&cp<=0xdfff)throw ProtocolError("invalid JSON surrogate");if(cp<=0xffff)wide.push_back(static_cast<wchar_t>(cp));else{cp-=0x10000;wide.push_back(static_cast<wchar_t>(0xd800+(cp>>10)));wide.push_back(static_cast<wchar_t>(0xdc00+(cp&1023)));}}else throw ProtocolError("invalid JSON escape");}else if(c<0x20)throw ProtocolError("invalid JSON control");else raw.push_back(static_cast<char>(c));}
  throw ProtocolError("unterminated JSON string");
 }
 JsonValue value(unsigned d){
  if(d>32)throw ProtocolError("JSON nesting too deep");ws();if(p_>=s_.size())throw ProtocolError("invalid JSON");auto c=s_[p_];
  if(c=='"')return JsonValue{string()};
  if(c=='{'){++p_;JsonValue::Object o;ws();if(p_<s_.size()&&s_[p_]=='}'){++p_;return JsonValue{std::move(o)};}for(;;){ws();if(p_>=s_.size()||s_[p_]!='"')throw ProtocolError("invalid JSON object");auto k=string();ws();if(take()!=':')throw ProtocolError("invalid JSON object");auto v=value(d+1);if(!o.emplace(std::move(k),std::move(v)).second)throw ProtocolError("duplicate JSON key");ws();auto x=take();if(x=='}')break;if(x!=',')throw ProtocolError("invalid JSON object");}return JsonValue{std::move(o)};}
  if(c=='['){++p_;JsonValue::Array a;ws();if(p_<s_.size()&&s_[p_]==']'){++p_;return JsonValue{std::move(a)};}for(;;){a.push_back(value(d+1));ws();auto x=take();if(x==']')break;if(x!=',')throw ProtocolError("invalid JSON array");}return JsonValue{std::move(a)};}
  if(s_.substr(p_,4)=="true"){p_+=4;return JsonValue{true};}if(s_.substr(p_,5)=="false"){p_+=5;return JsonValue{false};}if(s_.substr(p_,4)=="null"){p_+=4;return JsonValue{nullptr};}
  auto start=p_;while(p_<s_.size()&&s_[p_]>='0'&&s_[p_]<='9')++p_;if(start==p_)throw ProtocolError("unsupported JSON value");std::uint64_t n=0;auto r=std::from_chars(s_.data()+start,s_.data()+p_,n);if(r.ec!=std::errc{})throw ProtocolError("invalid JSON number");return JsonValue{n};
 }
public:explicit JsonParser(std::string_view s):s_(s){}JsonValue parse(){auto v=value(0);ws();if(p_!=s_.size())throw ProtocolError("trailing JSON data");return v;}
};

struct PlistValue{using Array=std::vector<PlistValue>;using Object=std::map<std::string,PlistValue,std::less<>>;std::variant<std::nullptr_t,bool,std::int64_t,std::uint64_t,std::string,Bytes,Array,Object> value;};
class BinaryPlist{
 std::span<const std::uint8_t>b_;std::size_t table_=0,count_=0,expandedBytes_=0;unsigned ow_=0,rw_=0;std::vector<std::size_t> offsets_;std::vector<bool>active_;PlistValue root_{nullptr};
 void charge_expanded(std::size_t bytes){if(bytes>MaxExpandedPlistBytes-expandedBytes_)throw TooLarge("plist expanded value exceeds limit");expandedBytes_+=bytes;}
 bool number(std::size_t p,unsigned n,std::uint64_t&v)const{if(!n||n>8||p>b_.size()||n>b_.size()-p)return false;v=0;for(unsigned i=0;i<n;++i)v=(v<<8)|b_[p+i];return true;}
 std::uint64_t ref(std::size_t p)const{std::uint64_t n=0;if(!number(p,rw_,n)||n>=count_)throw ProtocolError("invalid plist reference");return n;}
 std::uint64_t length(std::size_t&p,unsigned i)const{if(i<15)return i;if(p>=table_)throw ProtocolError("invalid plist length");auto m=b_[p++];if((m>>4)!=1||(m&15)>3)throw ProtocolError("invalid plist length");auto n=1u<<(m&15);std::uint64_t v=0;if(p>table_||n>table_-p||!number(p,n,v))throw ProtocolError("invalid plist length");p+=n;return v;}
 std::string utf16(std::size_t p,std::size_t n)const{if(n>(table_-p)/2)throw ProtocolError("truncated plist string");std::wstring w;w.reserve(n);for(std::size_t i=0;i<n;++i){auto cp=(std::uint32_t(b_[p+2*i])<<8)|b_[p+2*i+1];if(cp>=0xd800&&cp<=0xdbff){if(++i>=n)throw ProtocolError("invalid plist surrogate");auto low=(std::uint32_t(b_[p+2*i])<<8)|b_[p+2*i+1];if(low<0xdc00||low>0xdfff)throw ProtocolError("invalid plist surrogate");cp=0x10000+((cp-0xd800)<<10)+(low-0xdc00);}else if(cp>=0xdc00&&cp<=0xdfff)throw ProtocolError("invalid plist surrogate");if(cp<=0xffff)w.push_back(static_cast<wchar_t>(cp));else{cp-=0x10000;w.push_back(static_cast<wchar_t>(0xd800+(cp>>10)));w.push_back(static_cast<wchar_t>(0xdc00+(cp&1023)));}}return wide_utf8(w);}
 PlistValue object(std::size_t id,unsigned d){
  if(id>=count_||d>32)throw ProtocolError("plist object limit");if(active_[id])throw ProtocolError("cyclic plist object");charge_expanded(sizeof(PlistValue));active_[id]=true;auto p=offsets_[id];if(p>=table_)throw ProtocolError("invalid plist object");const auto marker=b_[p++];const unsigned kind=marker>>4;const unsigned info=marker&15;PlistValue v{nullptr};
  if(kind==0){if(info==8)v.value=false;else if(info==9)v.value=true;else if(info!=0)throw ProtocolError("unsupported plist simple value");}
  else if(kind==1){if(info>3)throw ProtocolError("oversized plist integer");auto n=1u<<info;std::uint64_t x=0;if(p>table_||n>table_-p||!number(p,n,x))throw ProtocolError("truncated plist integer");if(n==8&&(b_[p]&0x80))v.value=std::bit_cast<std::int64_t>(x);else v.value=x;}
  else if(kind==2||kind==3){if(info>3||p>table_||(std::uint64_t{1}<<info)>table_-p)throw ProtocolError("truncated plist scalar");}
  else if(kind==4){auto n=length(p,info);if(n>MaxAskBody||p>table_||n>table_-p)throw ProtocolError("plist data limit");charge_expanded(static_cast<std::size_t>(n));v.value=Bytes(b_.begin()+p,b_.begin()+p+static_cast<std::size_t>(n));}
  else if(kind==5||kind==6||kind==7){auto n=length(p,info);if(n>MaxMetadata)throw ProtocolError("plist string limit");if(kind==6){charge_expanded(static_cast<std::size_t>(n)*5);v.value=utf16(p,static_cast<std::size_t>(n));}else{if(p>table_||n>table_-p)throw ProtocolError("truncated plist string");charge_expanded(static_cast<std::size_t>(n)*5);std::string s(reinterpret_cast<const char*>(b_.data()+p),static_cast<std::size_t>(n));(void)utf8_wide(s);v.value=std::move(s);}}
  else if(kind==8){auto n=info+1;std::uint64_t x=0;if(n>8||p>table_||n>table_-p||!number(p,n,x))throw ProtocolError("invalid plist UID");v.value=x;}
  else if(kind==10||kind==13){auto n=length(p,info);if(n>1024)throw ProtocolError("plist collection limit");if(kind==10){if(n>(table_-p)/rw_)throw ProtocolError("truncated plist array");PlistValue::Array a;a.reserve(static_cast<std::size_t>(n));for(std::size_t i=0;i<n;++i)a.push_back(object(static_cast<std::size_t>(ref(p+i*rw_)),d+1));v.value=std::move(a);}else{if(n>(table_-p)/(2*rw_))throw ProtocolError("truncated plist dictionary");PlistValue::Object o;for(std::size_t i=0;i<n;++i){auto k=object(static_cast<std::size_t>(ref(p+i*rw_)),d+1);auto value=object(static_cast<std::size_t>(ref(p+(n+i)*rw_)),d+1);auto*t=std::get_if<std::string>(&k.value);if(!t)throw ProtocolError("invalid plist dictionary key");charge_expanded(t->size()+sizeof(std::string)+3*sizeof(void*));if(!o.emplace(*t,std::move(value)).second)throw ProtocolError("invalid plist dictionary key");}v.value=std::move(o);}}
  else throw ProtocolError("unsupported plist object");active_[id]=false;return v;
 }
public:
 explicit BinaryPlist(std::span<const std::uint8_t>b):b_(b){if(b.size()<40||std::string_view(reinterpret_cast<const char*>(b.data()),8)!="bplist00")throw ProtocolError("invalid Ask property list");auto t=b.size()-32;std::uint64_t count=0,top=0,table=0;ow_=b[t+6];rw_=b[t+7];if(!ow_||ow_>8||!rw_||rw_>8||!number(t+8,8,count)||!number(t+16,8,top)||!number(t+24,8,table)||!count||count>4096||top>=count||table<8||table>t)throw ProtocolError("invalid property-list trailer");count_=static_cast<std::size_t>(count);table_=static_cast<std::size_t>(table);if(count_>(t-table_)/ow_||table_+count_*ow_!=t)throw ProtocolError("invalid property-list offsets");for(std::size_t i=0;i<count_;++i){std::uint64_t off=0;if(!number(table_+i*ow_,ow_,off)||off<8||off>=table_)throw ProtocolError("invalid property-list object offset");offsets_.push_back(static_cast<std::size_t>(off));}active_.resize(count_);root_=object(static_cast<std::size_t>(top),0);if(!std::holds_alternative<PlistValue::Object>(root_.value))throw ProtocolError("Ask plist must be a dictionary");}
 const PlistValue& root()const{return root_;}
};
std::string plist_text(const PlistValue*v,std::string_view field){if(!v)throw ProtocolError(std::string(field)+" is missing");if(auto*s=std::get_if<std::string>(&v->value))return*s;throw ProtocolError(std::string(field)+" is not text");}
std::optional<std::uint64_t> plist_size(const PlistValue*v){if(!v)return std::nullopt;if(auto*n=std::get_if<std::uint64_t>(&v->value))return*n;if(auto*n=std::get_if<std::int64_t>(&v->value);n&&*n>=0)return static_cast<std::uint64_t>(*n);throw ProtocolError("invalid file size");}
struct HttpRequest{std::string path,version;std::map<std::string,std::string,std::less<>>headers;bool chunked=false;std::uint64_t length=0;};
struct RequestedFile{std::string archiveName,outputName,archiveFolder;std::optional<std::uint64_t>size;};
struct Approval{std::string token,sender,transferId;std::vector<RequestedFile>files;Clock::time_point expires{};};
class ArchiveDecoder;
struct Upload {
  std::filesystem::path stage, rawPath;
  HANDLE raw = INVALID_HANDLE_VALUE;
  Approval approval;
  std::string contentType;
  Clock::time_point bodyStart{}, lastProgress{}, lastData{};
  std::uint64_t received = 0, reportedBytes = 0, probedBytes = 0;
  std::array<std::uint8_t, 2> prefix{};
  std::unique_ptr<ArchiveDecoder> decoder;
  bool waitingForData = false;
  std::optional<std::uint64_t> totalWire;
  std::vector<std::string> published;
  std::vector<std::filesystem::path> owned;
};
struct Connection{std::uint32_t id=0;std::string peer="nearby device",buffer,phase="headers";std::optional<HttpRequest>request;Bytes body;std::uint64_t bodyRemaining=0;std::string chunkState="size";std::uint64_t chunkRemaining=0;std::size_t trailerBytes=0;std::optional<std::string>pendingToken;std::optional<Approval>approval;std::optional<Upload>upload;bool closeAfterResponse=false;};

void native_error(const char*op,FailureReason reason=FailureReason::Other){
 const auto error=GetLastError();
 throw NativeError(std::string(op)+" failed ("+std::to_string(error)+")",reason);
}
bool exact_io(HANDLE h,void*data,DWORD size,bool writing){auto*p=static_cast<std::uint8_t*>(data);while(size){DWORD n=0;const auto ok=writing?WriteFile(h,p,size,&n,nullptr):ReadFile(h,p,size,&n,nullptr);if(!ok||!n)return false;p+=n;size-=n;}return true;}
void write_file(HANDLE h,std::span<const std::uint8_t>b){auto*p=const_cast<std::uint8_t*>(b.data());auto left=b.size();while(left){DWORD n=0;auto want=static_cast<DWORD>((std::min)(left,static_cast<std::size_t>(MAXDWORD)));if(!WriteFile(h,p,want,&n,nullptr)||!n)native_error("Write file");p+=n;left-=n;}}
void read_file_exact(HANDLE h,std::span<std::uint8_t>b){auto*p=b.data();auto left=b.size();while(left){DWORD n=0;auto want=static_cast<DWORD>((std::min)(left,static_cast<std::size_t>(MAXDWORD)));if(!ReadFile(h,p,want,&n,nullptr)||!n)throw ProtocolError("truncated archive");p+=n;left-=n;}}
std::size_t read_file_some(HANDLE h,std::span<std::uint8_t>b){if(b.empty())return 0;DWORD n=0;auto want=static_cast<DWORD>((std::min)(b.size(),static_cast<std::size_t>(MAXDWORD)));if(!ReadFile(h,b.data(),want,&n,nullptr))native_error("Read file");return n;}
void seek_start(HANDLE h){LARGE_INTEGER z{};if(!SetFilePointerEx(h,z,nullptr,FILE_BEGIN))native_error("Seek file");}
void seek_end(HANDLE h){LARGE_INTEGER z{};if(!SetFilePointerEx(h,z,nullptr,FILE_END))native_error("Seek file end");}
std::uint64_t file_size(HANDLE h){LARGE_INTEGER n{};if(!GetFileSizeEx(h,&n)||n.QuadPart<0)native_error("Inspect file size");return static_cast<std::uint64_t>(n.QuadPart);}
struct Handle{HANDLE h=INVALID_HANDLE_VALUE;Handle()=default;explicit Handle(HANDLE v):h(v){}Handle(const Handle&)=delete;Handle&operator=(const Handle&)=delete;Handle(Handle&&o)noexcept:h(std::exchange(o.h,INVALID_HANDLE_VALUE)){}Handle&operator=(Handle&&o)noexcept{if(this!=&o){close();h=std::exchange(o.h,INVALID_HANDLE_VALUE);}return*this;}~Handle(){close();}void close(){if(h!=INVALID_HANDLE_VALUE){CloseHandle(h);h=INVALID_HANDLE_VALUE;}}HANDLE get()const{return h;}HANDLE release(){return std::exchange(h,INVALID_HANDLE_VALUE);}explicit operator bool()const{return h!=INVALID_HANDLE_VALUE;}};
std::string read_small_file(const std::filesystem::path&p,std::size_t limit){Handle f(CreateFileW(p.c_str(),GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OPEN_REPARSE_POINT,nullptr));if(!f){auto e=GetLastError();if(e==ERROR_FILE_NOT_FOUND||e==ERROR_PATH_NOT_FOUND)throw NotFound("control file is absent");SetLastError(e);native_error("Open control file");}BY_HANDLE_FILE_INFORMATION info{};if(!GetFileInformationByHandle(f.get(),&info)||(info.dwFileAttributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT)))throw ProtocolError("invalid control file");std::string out(limit+1,'\0');DWORD n=0;if(!ReadFile(f.get(),out.data(),static_cast<DWORD>(out.size()),&n,nullptr))native_error("Read control file");out.resize(n);return out;}
bool exists_path(const std::filesystem::path&p){return GetFileAttributesW(p.c_str())!=INVALID_FILE_ATTRIBUTES;}
std::filesystem::path final_path(HANDLE h){DWORD cap=GetFinalPathNameByHandleW(h,nullptr,0,FILE_NAME_NORMALIZED|VOLUME_NAME_DOS);if(!cap)native_error("Resolve directory path");std::wstring s(cap,L'\0');DWORD n=GetFinalPathNameByHandleW(h,s.data(),cap,FILE_NAME_NORMALIZED|VOLUME_NAME_DOS);if(!n||n>=cap)native_error("Resolve directory path");s.resize(n);if(s.starts_with(L"\\\\?\\"))s.erase(0,4);return std::filesystem::path(s);}
std::filesystem::path resolve_destination(std::filesystem::path p){std::filesystem::create_directories(p);Handle h(CreateFileW(p.c_str(),FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS,nullptr));if(!h)native_error("Open destination");BY_HANDLE_FILE_INFORMATION i{};if(!GetFileInformationByHandle(h.get(),&i))native_error("Inspect destination");if((i.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)==0)throw NativeError("destination is not a directory");auto resolved=final_path(h.get());const auto attr=GetFileAttributesW(resolved.c_str());if(attr==INVALID_FILE_ATTRIBUTES||(attr&FILE_ATTRIBUTE_REPARSE_POINT))throw NativeError("destination cannot be a reparse point");return resolved;}
void sync_write(HANDLE h,std::span<const std::uint8_t>b){write_file(h,b);if(!FlushFileBuffers(h))native_error("Flush file");}
void atomic_replace(const std::filesystem::path&path,std::string_view data,bool noReplace=false){if(data.size()>MaxMetadata)throw TooLarge("control state exceeds limit");GUID g{};if(FAILED(CoCreateGuid(&g)))native_error("Create temporary file ID");wchar_t id[40]{};StringFromGUID2(g,id,40);auto tmp=path.parent_path()/(L"."+path.filename().wstring()+L"."+std::wstring(id).substr(1,36)+L".tmp");Handle f(CreateFileW(tmp.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_TEMPORARY|FILE_FLAG_OPEN_REPARSE_POINT,nullptr));if(!f)native_error("Create temporary state file");try{sync_write(f.get(),std::span(reinterpret_cast<const std::uint8_t*>(data.data()),data.size()));f.close();DWORD flags=MOVEFILE_WRITE_THROUGH|(noReplace?0:MOVEFILE_REPLACE_EXISTING);if(!MoveFileExW(tmp.c_str(),path.c_str(),flags)){auto e=GetLastError();DeleteFileW(tmp.c_str());if(noReplace&&(e==ERROR_ALREADY_EXISTS||e==ERROR_FILE_EXISTS))throw ProtocolError("another approval request is already active");SetLastError(e);native_error("Publish control file");}}catch(...){DeleteFileW(tmp.c_str());throw;}}
std::string utc_after(std::chrono::seconds delta){FILETIME ft{};GetSystemTimeAsFileTime(&ft);ULARGE_INTEGER n{};n.LowPart=ft.dwLowDateTime;n.HighPart=ft.dwHighDateTime;n.QuadPart+=static_cast<std::uint64_t>(delta.count())*10000000ULL;ft.dwLowDateTime=n.LowPart;ft.dwHighDateTime=n.HighPart;SYSTEMTIME s{};if(!FileTimeToSystemTime(&ft,&s))native_error("Format UTC timestamp");char b[32]{};std::snprintf(b,sizeof(b),"%04u-%02u-%02uT%02u:%02u:%02uZ",s.wYear,s.wMonth,s.wDay,s.wHour,s.wMinute,s.wSecond);return b;}
std::string new_token(){GUID g{};if(FAILED(CoCreateGuid(&g)))native_error("Create approval token");wchar_t wide[40]{};if(!StringFromGUID2(g,wide,40))native_error("Format approval token");std::string out;for(const auto c:std::wstring_view(wide)){if(c=='{'||c=='}'||c=='-')continue;out.push_back(static_cast<char>(c>='A'&&c<='F'?c+32:c));}return out;}
HttpRequest parse_headers(std::string_view block){
 if(!block.ends_with("\r\n\r\n"))throw ProtocolError("malformed HTTP header terminator");std::vector<std::string_view>lines;auto end=block.size()-4;std::size_t p=0;while(p<end){auto q=block.find("\r\n",p);if(q==std::string_view::npos||q>end)q=end;lines.push_back(block.substr(p,q-p));p=q+2;}if(lines.empty())throw ProtocolError("malformed HTTP request");
 for(unsigned char c:lines[0])if(c>0x7f)throw ProtocolError("non-ASCII HTTP request line");auto line=lines[0];auto a=line.find(' ');auto b=a==std::string_view::npos?a:line.find(' ',a+1);if(a==std::string_view::npos||b==std::string_view::npos||line.find(' ',b+1)!=std::string_view::npos||line.substr(0,a)!="POST"||(line.substr(b+1)!="HTTP/1.0"&&line.substr(b+1)!="HTTP/1.1"))throw ProtocolError("unsupported HTTP request line");
 HttpRequest r;r.path=std::string(line.substr(a+1,b-a-1));r.version=std::string(line.substr(b+1));if(r.path.empty()||r.path.front()!='/'||r.path.find('#')!=std::string::npos||r.path.find('\0')!=std::string::npos)throw ProtocolError("invalid HTTP path");
 bool hasLength=false,hasTransfer=false;for(std::size_t i=1;i<lines.size();++i){auto l=lines[i];if(l.empty()||l.front()==' '||l.front()=='\t')throw ProtocolError("malformed HTTP header");auto c=l.find(':');if(c==std::string_view::npos||c==0)throw ProtocolError("malformed HTTP header");auto key=l.substr(0,c);for(unsigned char ch:key)if(!((ch>='A'&&ch<='Z')||(ch>='a'&&ch<='z')||(ch>='0'&&ch<='9')||std::string_view("!#$%&'*+-.^_|~").find(static_cast<char>(ch))!=std::string_view::npos||ch==96))throw ProtocolError("invalid HTTP header name");auto name=lower_ascii(key);if(r.headers.contains(name))throw ProtocolError("duplicate HTTP header");auto val=trim_ows(l.substr(c+1));for(unsigned char ch:val)if(ch==0||ch=='\r'||ch=='\n')throw ProtocolError("invalid HTTP header value");r.headers.emplace(name,std::string(val));if(name=="content-length"){hasLength=true;r.length=parse_uint(val,MaxArchiveBytes,"Content-Length");}if(name=="transfer-encoding"){hasTransfer=true;if(lower_ascii(val)!="chunked")throw ProtocolError("unsupported transfer encoding");}}
 if(hasLength&&hasTransfer)throw ProtocolError("ambiguous HTTP body framing");if(hasTransfer)r.chunked=true;else if(!hasLength)throw ProtocolError("missing HTTP body framing");return r;
}
Bytes plist_length(std::uint8_t marker,std::size_t n){Bytes b;if(n<15)b.push_back(static_cast<std::uint8_t>(marker|n));else{b.push_back(static_cast<std::uint8_t>(marker|15));b.push_back(0x12);for(int i=3;i>=0;--i)b.push_back(static_cast<std::uint8_t>(n>>(i*8)));}return b;}
Bytes plist_ascii(std::string_view s){auto b=plist_length(0x50,s.size());b.insert(b.end(),s.begin(),s.end());return b;}
Bytes plist_data(std::span<const std::uint8_t>s){auto b=plist_length(0x40,s.size());b.insert(b.end(),s.begin(),s.end());return b;}
Bytes plist_text_obj(std::string_view s){auto w=utf8_wide(s);auto b=plist_length(0x60,w.size());for(auto c:w){b.push_back(static_cast<std::uint8_t>(c>>8));b.push_back(static_cast<std::uint8_t>(c));}return b;}
// The receiver saves the original video bitstream. Advertise HEVC Main and
// Main 10 through level 5.1 (4K60) so Photos can share those videos directly.
constexpr std::string_view receiveMediaCapabilities =
    R"({"Version":1,"Codecs":{"hvc1":{"Profiles":{"VTSupportedProfiles":[1,2],)"
    R"("VTPerProfileSupport":{"1":{"VTMaxPlaybackLevel":153},"2":{"VTMaxPlaybackLevel":153}}}}}})";
Bytes make_plist_response(std::string_view name,bool discovery){std::vector<Bytes>o;o.push_back(plist_text_obj(name));o.push_back(plist_ascii("ReceiverComputerName"));o.push_back(plist_ascii("Windows"));o.push_back(plist_ascii("ReceiverModelName"));std::vector<std::uint8_t>keyRefs{1,3},values{0,2};if(discovery){o.push_back(plist_ascii("ReceiverMediaCapabilities"));o.push_back(plist_data(std::span(reinterpret_cast<const std::uint8_t*>(receiveMediaCapabilities.data()),receiveMediaCapabilities.size())));o.push_back(plist_ascii("IsAirDropable"));o.push_back({9});keyRefs.push_back(4);keyRefs.push_back(6);values.push_back(5);values.push_back(7);}auto d=plist_length(0xd0,keyRefs.size());d.insert(d.end(),keyRefs.begin(),keyRefs.end());d.insert(d.end(),values.begin(),values.end());o.push_back(std::move(d));Bytes out{'b','p','l','i','s','t','0','0'};std::vector<std::uint32_t>offs;for(auto&v:o){offs.push_back(static_cast<std::uint32_t>(out.size()));out.insert(out.end(),v.begin(),v.end());}const std::uint64_t table=out.size();for(auto v:offs)for(int i=3;i>=0;--i)out.push_back(static_cast<std::uint8_t>(v>>(i*8)));out.insert(out.end(),6,0);out.push_back(4);out.push_back(1);for(int i=7;i>=0;--i)out.push_back(static_cast<std::uint8_t>(o.size()>>(i*8)));for(int i=7;i>=0;--i)out.push_back(static_cast<std::uint8_t>((o.size()-1)>>(i*8)));for(int i=7;i>=0;--i)out.push_back(static_cast<std::uint8_t>(table>>(i*8)));return out;}
std::string http_response(unsigned status,std::span<const std::uint8_t>body={},bool close=false){const char*reason=status==200?"OK":status==400?"Bad Request":status==403?"Forbidden":status==404?"Not Found":status==413?"Payload Too Large":status==500?"Internal Server Error":"Error";std::string out="HTTP/1.1 "+std::to_string(status)+" "+reason+"\r\nContent-Length: "+std::to_string(body.size())+"\r\nContent-Type: application/x-apple-binary-plist\r\n";if(close)out+="Connection: close\r\n";out+="\r\n";out.append(reinterpret_cast<const char*>(body.data()),body.size());return out;}

void write_bounded(HANDLE target, std::span<const std::uint8_t> data, std::uint64_t &total,
                   std::uint64_t limit = MaxArchiveBytes) {
  if (data.size() > limit - total)
    throw TooLarge("expanded archive exceeds limit");
  if (!data.empty())
    write_file(target, data);
  total += data.size();
}
class ArchiveInflater {
  HANDLE output_;
  z_stream stream_{};
  std::uint64_t &total_;
  std::uint64_t limit_;
  bool complete_ = false;

public:
  ArchiveInflater(HANDLE output, int windowBits, std::uint64_t &total, std::uint64_t limit)
      : output_(output), total_(total), limit_(limit) {
    if (inflateInit2(&stream_, windowBits) != Z_OK)
      throw NativeError("Initialize inflater");
  }
  ~ArchiveInflater() { inflateEnd(&stream_); }
  ArchiveInflater(const ArchiveInflater &) = delete;

  bool complete() const { return complete_; }

  void append(std::span<const std::uint8_t> input, const std::function<void()> &cancel) {
    if (input.empty())
      return;
    if (complete_)
      throw ProtocolError("trailing bytes after compressed archive");
    stream_.next_in = const_cast<Bytef *>(input.data());
    stream_.avail_in = static_cast<uInt>(input.size());
    std::array<std::uint8_t, CopyChunk> output;
    do {
      cancel();
      stream_.next_out = output.data();
      stream_.avail_out = static_cast<uInt>(output.size());
      const auto result = inflate(&stream_, Z_NO_FLUSH);
      const auto size = output.size() - stream_.avail_out;
      write_bounded(output_, std::span(output.data(), size), total_, limit_);
      if (result == Z_STREAM_END) {
        if (stream_.avail_in)
          throw ProtocolError("trailing bytes after compressed archive");
        complete_ = true;
        return;
      }
      if (result == Z_BUF_ERROR && !stream_.avail_in)
        return;
      if (result != Z_OK)
        throw ProtocolError("invalid compressed archive");
    } while (stream_.avail_in || !stream_.avail_out);
  }
};

int archive_window_bits(std::string_view media, std::span<const std::uint8_t, 2> prefix) {
  if (media == "application/x-dvzip")
    return 0;
  if ((prefix[0] == 0x1f && prefix[1] == 0x8b) || media == "application/gzip")
    return MAX_WBITS + 16;
  if (prefix[0] == 'x' && (prefix[1] == 0x9c || prefix[1] == 0xda))
    return MAX_WBITS;
  return 0;
}
class ArchiveDecoder {
  Handle output_;
  std::uint64_t total_ = 0;
  std::unique_ptr<ArchiveInflater> inflater_;
  bool dvzip_;
  std::array<std::uint8_t, 4> header_{};
  std::size_t headerSize_ = 0;
  std::size_t remaining_ = 0;

public:
  ArchiveDecoder(Handle output, int windowBits)
      : output_(std::move(output)), dvzip_(windowBits == 0) {
    if (!dvzip_)
      inflater_ = std::make_unique<ArchiveInflater>(output_.get(), windowBits, total_, MaxArchiveBytes);
  }

  HANDLE output() const { return output_.get(); }
  bool complete_stream() const { return !dvzip_ && inflater_->complete(); }
  bool at_archive_boundary() const {
    return dvzip_ ? total_ && !remaining_ && !headerSize_ : complete_stream();
  }

  void append(std::span<const std::uint8_t> input, const std::function<void()> &cancel) {
    if (!dvzip_) {
      inflater_->append(input, cancel);
      return;
    }
    while (!input.empty()) {
      cancel();
      if (!remaining_) {
        const auto size = (std::min)(input.size(), header_.size() - headerSize_);
        std::copy_n(input.begin(), size, header_.begin() + headerSize_);
        input = input.subspan(size);
        headerSize_ += size;
        if (headerSize_ < header_.size())
          return;
        const auto encoded = (std::uint32_t(header_[0]) << 24) | (std::uint32_t(header_[1]) << 16) |
                             (std::uint32_t(header_[2]) << 8) | header_[3];
        remaining_ = encoded & 0x7fffffffu;
        if (!remaining_ || remaining_ > DvzipBlockLimit)
          throw ProtocolError("invalid DVZip block length");
        headerSize_ = 0;
        if (!(encoded & 0x80000000u))
          inflater_ = std::make_unique<ArchiveInflater>(output_.get(), MAX_WBITS, total_,
              (std::min)(MaxArchiveBytes, total_ + DvzipOutputBlockLimit));
      }
      const auto size = (std::min)(input.size(), remaining_);
      if (inflater_)
        inflater_->append(input.first(size), cancel);
      else
        write_bounded(output_.get(), input.first(size), total_);
      input = input.subspan(size);
      remaining_ -= size;
      if (inflater_ && !remaining_) {
        if (!inflater_->complete())
          throw ProtocolError("truncated DVZip block");
        inflater_.reset();
      }
    }
  }
};

// A missing final HTTP chunk can be recovered once a trailer is plausible.
// Full CPIO validation remains the publication gate.
bool has_cpio_trailer(HANDLE file) {
  constexpr std::string_view trailer = "TRAILER!!!";
  constexpr auto tailLimit = MaxCpioTrailingZeroes + trailer.size() + 4;
  const auto size = file_size(file);
  const auto tailSize = static_cast<std::size_t>((std::min)(size, std::uint64_t(tailLimit)));
  LARGE_INTEGER offset{};
  offset.QuadPart = -static_cast<LONGLONG>(tailSize);
  if (!SetFilePointerEx(file, offset, nullptr, FILE_END))
    native_error("Seek CPIO trailer");
  std::array<std::uint8_t, tailLimit> tail;
  read_file_exact(file, std::span(tail).first(tailSize));
  auto last = tail.begin() + tailSize;
  while (last != tail.begin() && *(last - 1) == 0)
    --last;
  return last != tail.begin() + tailSize && last - tail.begin() >= static_cast<std::ptrdiff_t>(trailer.size()) &&
         std::equal(trailer.begin(), trailer.end(), last - trailer.size());
}

std::uint64_t parse_octal(std::span<const std::uint8_t> b, std::string_view field) {
  if (b.empty())
    throw ProtocolError("invalid CPIO " + std::string(field));
  std::uint64_t n = 0;
  for (auto c : b) {
    if (c < '0' || c > '7')
      throw ProtocolError("invalid CPIO " + std::string(field));
    if (n > (UINT64_MAX - (c - '0')) / 8)
      throw TooLarge("CPIO number overflow");
    n = n * 8 + (c - '0');
  }
  return n;
}
std::uint64_t parse_hex(std::span<const std::uint8_t> b, std::string_view field) {
  if (b.empty())
    throw ProtocolError("invalid CPIO " + std::string(field));
  std::uint64_t n = 0;
  for (auto c : b) {
    unsigned d;
    if (c >= '0' && c <= '9')
      d = c - '0';
    else if (c >= 'a' && c <= 'f')
      d = c - 'a' + 10;
    else if (c >= 'A' && c <= 'F')
      d = c - 'A' + 10;
    else
      throw ProtocolError("invalid CPIO " + std::string(field));
    if (n > (UINT64_MAX - d) / 16)
      throw TooLarge("CPIO number overflow");
    n = n * 16 + d;
  }
  return n;
}
std::size_t padding(std::uint64_t n) {
  return static_cast<std::size_t>((4 - (n & 3)) & 3);
}
std::vector<std::pair<std::filesystem::path, std::pair<std::string, std::uint64_t>>>
parse_cpio(HANDLE cpio, const std::vector<RequestedFile> &requested, const std::filesystem::path &stage,
           const std::function<void()> &cancel, std::vector<std::filesystem::path> &owned) {
  seek_start(cpio);
  std::vector<std::pair<std::filesystem::path, std::pair<std::string, std::uint64_t>>> outputs;
  std::vector<bool> consumed(requested.size());
  std::uint64_t total = 0, metadataTotal = 0;
  bool trailer = false;
  std::set<std::string> directoryEntries;
  std::set<std::pair<std::string, std::string>> filePaths, metadataTargets;
  std::size_t entryIndex = 0;
  for (;;) {
    cancel();
    std::array<std::uint8_t, 6> first{};
    auto got = read_file_some(cpio, first);
    if (!got)
      break;
    if (got != first.size())
      throw ProtocolError("truncated CPIO header");
    bool newc = false, crc = false;
    std::array<std::uint8_t, 110> header{};
    if (std::memcmp(first.data(), "070707", 6) == 0) {
      std::copy(first.begin(), first.end(), header.begin());
      read_file_exact(cpio, std::span(header.data() + 6, 70));
    } else if (std::memcmp(first.data(), "070701", 6) == 0 || std::memcmp(first.data(), "070702", 6) == 0) {
      newc = true;
      crc = first[5] == '2';
      std::copy(first.begin(), first.end(), header.begin());
      read_file_exact(cpio, std::span(header.data() + 6, 104));
    } else
      throw ProtocolError("unsupported CPIO format");
    std::uint64_t mode = 0, nlink = 0, namesize = 0, size = 0, crcExpected = 0;
    if (!newc) {
      for (const auto &field : std::array<std::pair<std::size_t, std::size_t>, 10>{
               {{6, 6}, {12, 6}, {18, 6}, {24, 6}, {30, 6}, {36, 6}, {42, 6}, {48, 11}, {59, 6}, {65, 11}}})
        parse_octal(std::span(header.data() + field.first, field.second), "field");
      mode = parse_octal(std::span(header.data() + 18, 6), "mode");
      nlink = parse_octal(std::span(header.data() + 36, 6), "link count");
      namesize = parse_octal(std::span(header.data() + 59, 6), "name size");
      size = parse_octal(std::span(header.data() + 65, 11), "file size");
    } else {
      std::array<std::uint64_t, 13> fields{};
      constexpr std::array<std::size_t, 13> offsets{6, 14, 22, 30, 38, 46, 54, 62, 70, 78, 86, 94, 102};
      for (std::size_t i = 0; i < fields.size(); ++i)
        fields[i] = parse_hex(std::span(header.data() + offsets[i], 8), "field");
      mode = fields[1];
      nlink = fields[4];
      size = fields[6];
      namesize = fields[11];
      crcExpected = fields[12];
    }
    if (!namesize || namesize > MaxCpioName || size > MaxFileBytes)
      throw TooLarge("CPIO member exceeds limit");
    Bytes nameBytes(static_cast<std::size_t>(namesize));
    read_file_exact(cpio, nameBytes);
    if (nameBytes.back() != 0 || std::find(nameBytes.begin(), nameBytes.end() - 1, 0) != nameBytes.end() - 1)
      throw ProtocolError("invalid CPIO member name");
    std::string raw(reinterpret_cast<const char *>(nameBytes.data()), nameBytes.size() - 1);
    (void)utf8_wide(raw);
    if (newc) {
      auto pad = padding(110 + namesize);
      if (pad) {
        std::array<std::uint8_t, 3> p{};
        read_file_exact(cpio, std::span(p.data(), pad));
        if (std::any_of(p.begin(), p.begin() + pad, [](auto c) { return c != 0; }))
          throw ProtocolError("invalid CPIO name padding");
      }
    }
    if (raw == "TRAILER!!!") {
      if (size || trailer)
        throw ProtocolError("invalid CPIO trailer");
      trailer = true;
      break;
    }
    const auto type = mode & 0170000;
    if (type == 0040000) {
      if (size)
        throw ProtocolError("archive directory has file content");
      if (raw != "." && raw != "./") {
        std::string_view folder = raw;
        if (folder.starts_with("./")) folder.remove_prefix(2);
        if (folder.ends_with('/')) folder.remove_suffix(1);
        directoryEntries.insert(archive_folder(folder));
        if (directoryEntries.size() > requested.size())
          throw ProtocolError("too many archive directories for approved files");
      }
      continue;
    }
    if (type != 0100000 || nlink != 1)
      throw ProtocolError("only independent regular files are accepted");
    const auto path = archive_path(raw);
    const auto &name = path.name;
    const auto matches = [&](const RequestedFile &file, std::string_view candidate) {
      return file.archiveName == candidate &&
             (file.archiveFolder.empty() || file.archiveFolder == path.folder);
    };
    std::optional<std::size_t> match;
    for (std::size_t i = 0; i < requested.size(); ++i)
      if (!consumed[i] && matches(requested[i], name) &&
          (!requested[i].size || *requested[i].size == size)) {
        if (!match)
          match = i;
        if (requested[i].archiveFolder == path.folder) {
          match = i;
          break;
        }
      }
    bool metadata = false;
    if (!match && name.starts_with("._")) {
      auto counterpart = name.substr(2);
      if (counterpart.empty() || std::none_of(requested.begin(), requested.end(),
                                              [&](const auto &f) { return matches(f, counterpart); }))
        throw ProtocolError("unapproved AppleDouble metadata");
      if (size > 16 * 1024 * 1024 - metadataTotal)
        throw TooLarge("AppleDouble metadata exceeds limit");
      metadataTotal += size;
      metadataTargets.emplace(path.folder, counterpart);
      if (metadataTargets.size() > requested.size())
        throw ProtocolError("too many AppleDouble metadata targets");
      metadata = true;
    } else if (!match)
      throw ProtocolError("archive file list differs from approved request");
    if (match && requested[*match].size && *requested[*match].size != size)
      throw ProtocolError("archive file size differs from approved request");
    if (!metadata) {
      if (size > MaxFileBytes - total)
        throw TooLarge("total file bytes exceed limit");
      total += size;
      consumed[*match] = true;
      filePaths.emplace(path.folder, name);
    }
    auto outputPath = stage / (L"file-" + std::to_wstring(entryIndex++) + L".part");
    Handle output;
    if (!metadata) {
      output = Handle(CreateFileW(outputPath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                                  FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
      if (!output)
        native_error("Create staged receive file");
      owned.push_back(outputPath);
    }
    std::uint64_t remaining = size;
    std::uint32_t checksum = 0;
    std::array<std::uint8_t, CopyChunk> buf{};
    while (remaining) {
      cancel();
      auto count = static_cast<std::size_t>((std::min)(remaining, static_cast<std::uint64_t>(buf.size())));
      read_file_exact(cpio, std::span(buf.data(), count));
      if (output)
        write_file(output.get(), std::span(buf.data(), count));
      if (crc)
        for (std::size_t i = 0; i < count; ++i)
          checksum += buf[i];
      remaining -= count;
    }
    if (output && !FlushFileBuffers(output.get()))
      native_error("Flush staged receive file");
    if (crc && checksum != crcExpected)
      throw ProtocolError("CPIO checksum mismatch");
    if (newc) {
      auto pad = padding(size);
      if (pad) {
        std::array<std::uint8_t, 3> p{};
        read_file_exact(cpio, std::span(p.data(), pad));
        if (std::any_of(p.begin(), p.begin() + pad, [](auto c) { return c != 0; }))
          throw ProtocolError("invalid CPIO data padding");
      }
    }
    if (!metadata) {
      if (!match)
        throw ProtocolError("internal CPIO match error");
      outputs.push_back({outputPath, {requested[*match].outputName, size}});
    }
  }
  if (!trailer ||
      std::count(consumed.begin(), consumed.end(), true) != static_cast<std::ptrdiff_t>(requested.size()))
    throw ProtocolError("CPIO file list is incomplete");
  // Directory records are structural. Publish only the approved regular files.
  for (const auto &folder : directoryEntries) {
    const auto first = filePaths.lower_bound({folder, {}});
    if (first == filePaths.end() || first->first != folder)
      throw ProtocolError("archive directory has no approved file");
  }
  if (!std::includes(filePaths.begin(), filePaths.end(), metadataTargets.begin(), metadataTargets.end()))
    throw ProtocolError("AppleDouble metadata is not next to its approved file");
  std::uint64_t trailing = 0;
  std::array<std::uint8_t, CopyChunk> buf{};
  for (;;) {
    auto n = read_file_some(cpio, buf);
    if (!n)
      break;
    trailing += n;
    if (trailing > MaxCpioTrailingZeroes ||
        std::any_of(buf.begin(), buf.begin() + static_cast<std::ptrdiff_t>(n), [](auto c) { return c != 0; }))
      throw ProtocolError("unexpected data after CPIO trailer");
  }
  return outputs;
}

class ReceiveWorker {
  std::filesystem::path control_, destination_, sessionStage_;
  std::string receiverName_;
  HANDLE in_ = GetStdHandle(STD_INPUT_HANDLE), out_ = GetStdHandle(STD_OUTPUT_HANDLE),
         err_ = GetStdHandle(STD_ERROR_HANDLE);
  std::map<std::uint32_t, Connection> connections_;
  const Clock::time_point started_ = Clock::now();
  std::optional<Approval> pending_;
  std::optional<std::string> lastResult_;
  std::optional<std::string> lastCompletedFields_;
  std::vector<std::string> savedPaths_;
  bool stopping_ = false;
  std::optional<std::uint64_t> idleDeadlineMs_;
  std::string standbyJson_;
  bool idleStopRequested_ = false;
  Handle preview_;
  std::filesystem::path state_path() const { return control_ / receive_state::FileName; }
  std::filesystem::path incoming_path() const { return control_ / offer::FileName; }
  std::filesystem::path preview_path(std::string_view token) const {
    return control_ / offer::PreviewName(token);
  }
  void log(std::string_view text) {
    std::string s = "receive-worker: " + std::string(text) + "\r\n";
    DWORD n = 0;
    WriteFile(err_, s.data(), static_cast<DWORD>(s.size()), &n, nullptr);
  }
  void check_cancel() {
    if (exists_path(control_ / markers::ReceiveStopFileName) || exists_path(control_ / markers::CancelFileName))
      throw Cancelled("receive stopped");
  }
  void log_offer_event(std::uint32_t id, std::string_view event) {
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - started_).count();
    log("offer: elapsed_ms=" + std::to_string(ms) + " connection=" + std::to_string(id) + " " + std::string(event));
  }
  bool transfer_active() const {
    return pending_ || std::any_of(connections_.begin(), connections_.end(), [](const auto &entry) {
             return entry.second.approval || entry.second.upload;
           });
  }
  void write_state(Phase phase, std::string fields = {}) {
    const bool listening = phase == Phase::Listening;
    const bool completed = phase == Phase::Completed;
    if (stopping_ || !(listening || completed) || transfer_active()) {
      idleDeadlineMs_.reset();
    } else if (!idleDeadlineMs_) {
      idleDeadlineMs_ = GetTickCount64() + std::chrono::milliseconds(ReceiveIdleTimeout).count();
    }
    auto published = std::string("{\"") + receive_state::VersionField + "\":" +
                     std::to_string(receive_state::Version) +
                     state_field(receive_state::PhaseField) + json_escape(receive_state::PhaseName(phase)) + fields;
    if (listening)
      published += state_field(receive_state::ReceiverNameField) + json_escape(receiverName_);
    if (idleDeadlineMs_)
      published += state_field(receive_state::IdleDeadlineMsField) + std::to_string(*idleDeadlineMs_);
    if (!savedPaths_.empty()) {
      std::vector<std::string> visible;
      std::size_t bytes = published.size() + state_field(receive_state::SavedPathsField).size() + 3;
      // The state file and the UI parser have independent size limits.
      for (auto it = savedPaths_.rbegin(); it != savedPaths_.rend() && visible.size() < 256; ++it) {
        auto path = json_escape(*it);
        if (bytes + path.size() + 1 > MaxMetadata) break;
        bytes += path.size() + 1;
        visible.push_back(std::move(path));
      }
      if (!visible.empty()) {
        published += state_field(receive_state::SavedPathsField) + '[';
        for (auto it = visible.rbegin(); it != visible.rend(); ++it) {
          if (it != visible.rbegin()) published += ',';
          published += *it;
        }
        published += ']';
      }
    }
    published += '}';
    if (published.size() > MaxMetadata)
      throw TooLarge("control state exceeds limit");
    atomic_replace(state_path(), published);
    if (idleDeadlineMs_)
      standbyJson_ = std::move(published);
    else
      standbyJson_.clear();
    if (completed)
      lastCompletedFields_ = std::move(fields);
  }
  void publish_discovery_notice() {
    if (standbyJson_.empty() || transfer_active() || stopping_)
      return;
    // Retain the standby deadline, previous result and saved paths. The next
    // normal state publication replaces this transient hint.
    auto state = standbyJson_.substr(0, standbyJson_.size() - 1);
    state += state_field(receive_state::DiscoveredAtMsField) + std::to_string(GetTickCount64()) + '}';
    if (state.size() <= MaxMetadata) {
      try {
        atomic_replace(state_path(), state);
      } catch (const NativeError &e) {
        log(e.what());
      }
    }
  }
  void listening(std::optional<std::string> result = std::nullopt) {
    if (result)
      lastResult_ = *result;
    write_state(Phase::Listening, lastResult_ ? state_field(receive_state::LastResultField) +
                                                   json_escape(*lastResult_) : std::string{});
  }
  void write_failure(FailureReason reason, std::string_view diagnostic, std::string_view token = {}) {
    lastResult_ = receive_state::FailedResult;
    auto state = state_field(receive_state::LastResultField) + json_escape(*lastResult_) +
                 state_field(receive_state::FailureReasonField) + std::to_string(static_cast<std::uint64_t>(reason)) +
                 state_field(receive_state::ErrorField) + json_escape(safe_display(diagnostic, 160));
    if (!token.empty())
      state += state_field(receive_state::TokenField) + json_escape(token);
    write_state(Phase::Listening, std::move(state));
  }
  void clear_stale_prompt() {
    const auto incoming = incoming_path();
    if (!exists_path(incoming))
      return;
    try {
      auto raw = read_small_file(incoming, MaxMetadata);
      if (raw.size() <= MaxMetadata) {
        auto parsed = JsonParser(raw).parse();
        if (auto *o = std::get_if<JsonValue::Object>(&parsed.value)) {
          auto i = o->find(receive_state::TokenField);
          if (i != o->end())
            if (auto *t = std::get_if<std::string>(&i->second.value); t && offer::ValidToken(*t)) {
              auto d = control_ / offer::DecisionName(*t);
              DeleteFileW(d.c_str());
            }
        }
      }
    } catch (...) {
    }
    DeleteFileW(incoming.c_str());
  }
  void emit(std::uint8_t kind, std::uint32_t id, std::span<const std::uint8_t> payload = {}) {
    if (payload.size() > MaxFrame)
      throw TooLarge("worker output frame exceeds limit");
    std::array<std::uint8_t, 9> h{};
    h[0] = kind;
    for (unsigned i = 0; i < 4; ++i) {
      h[1 + i] = static_cast<std::uint8_t>(id >> (8 * i));
      h[5 + i] = static_cast<std::uint8_t>(payload.size() >> (8 * i));
    }
    write_file(out_, h);
    if (!payload.empty())
      write_file(out_, payload);
  }
  void emit_data(std::uint32_t id, std::string_view s) {
    emit(Data, id, std::span(reinterpret_cast<const std::uint8_t *>(s.data()), s.size()));
  }
  void remove_prompt(std::string_view token) {
    if (!offer::ValidToken(token))
      return;
    DeleteFileW((control_ / offer::DecisionName(token)).c_str());
    if (pending_ && pending_->token == token)
      preview_.close();
    try {
      auto raw = read_small_file(incoming_path(), MaxMetadata);
      if (raw.size() > MaxMetadata)
        return;
      auto v = JsonParser(raw).parse();
      auto *o = std::get_if<JsonValue::Object>(&v.value);
      if (!o)
        return;
      auto i = o->find(receive_state::TokenField);
      if (i != o->end())
        if (auto *t = std::get_if<std::string>(&i->second.value); t && *t == token)
          DeleteFileW(incoming_path().c_str());
    } catch (...) {
    }
  }
  void drop_pending(Connection &c, std::string_view reason) {
    if (pending_ && pending_->token == c.pendingToken.value_or("")) {
      remove_prompt(pending_->token);
      pending_.reset();
      c.pendingToken.reset();
      lastResult_ = std::string(reason);
      listening();
    }
  }
  void discard_upload(Connection &c) {
    if (!c.upload)
      return;
    auto upload = std::move(*c.upload);
    c.upload.reset();
    upload.decoder.reset();
    if (upload.raw != INVALID_HANDLE_VALUE) {
      CloseHandle(upload.raw);
      upload.raw = INVALID_HANDLE_VALUE;
    }
    for (const auto &p : upload.owned)
      if (p.parent_path() == upload.stage) {
        const auto a = GetFileAttributesW(p.c_str());
        if (a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_REPARSE_POINT) == 0 &&
            (a & FILE_ATTRIBUTE_DIRECTORY) == 0)
          DeleteFileW(p.c_str());
      }
    if (!upload.rawPath.empty()) {
      const auto a = GetFileAttributesW(upload.rawPath.c_str());
      if (a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_REPARSE_POINT) == 0 &&
          (a & FILE_ATTRIBUTE_DIRECTORY) == 0)
        DeleteFileW(upload.rawPath.c_str());
    }
    if (sessionStage_.empty())
      RemoveDirectoryW(upload.stage.c_str());
  }
  void close_conn(std::uint32_t id, std::span<const std::uint8_t> closeNotice = {}) {
    auto it = connections_.find(id);
    if (it == connections_.end())
      return;
    auto &c = it->second;
    const bool upload = c.upload.has_value(), approval = c.approval.has_value();
    try {
      drop_pending(c, "connection-closed");
    } catch (...) {
    }
    discard_upload(c);
    connections_.erase(it);
    if (upload || approval)
      write_failure(FailureReason::ConnectionClosed,
                    upload ? "connection closed during upload" : "connection closed before upload");
    emit(Close, id, closeNotice);
  }
  void abort_all(std::string_view diagnostic, FailureReason reason = FailureReason::Other) {
    for (auto &[id, c] : connections_) {
      try {
        drop_pending(c, receive_state::FailedResult);
      } catch (...) {
      }
      discard_upload(c);
    }
    connections_.clear();
    try {
      write_failure(reason, diagnostic);
    } catch (...) {
    }
  }
  void stop() {
    stopping_ = true;
    bool partial = false;
    for (auto &[id, c] : connections_) {
      partial = partial || (c.upload && !c.upload->published.empty());
      try {
        drop_pending(c, receive_state::CancelledResult);
      } catch (...) {
      }
      discard_upload(c);
      try {
        emit(Close, id);
      } catch (...) {
      }
    }
    connections_.clear();
    if (partial) {
      try {
        listening(receive_state::CancelledResult);
      } catch (...) {
      }
    } else if (lastCompletedFields_)
      try {
        write_state(Phase::Completed, *lastCompletedFields_);
      } catch (...) {
      }
    else if (lastResult_ != receive_state::FailedResult) {
      lastResult_ = receive_state::CancelledResult;
      try {
        listening();
      } catch (...) {
      }
    }
  }
  std::string status_json_files(const std::vector<RequestedFile> &files, bool display) const {
    std::string s = "[";
    for (std::size_t i = 0; i < files.size(); ++i) {
      if (i)
        s += ',';
      s += '{' + json_escape(receive_state::FileNameField) + ':' +
           json_escape(display ? files[i].outputName : files[i].archiveName);
      if (files[i].size)
        s += state_field(receive_state::FileSizeField) + std::to_string(*files[i].size);
      s += "}";
    }
    return s + "]";
  }
  std::set<std::wstring> existing_names() const {
    std::set<std::wstring> used;
    WIN32_FIND_DATAW data{};
    auto pattern = destination_ / L"*";
    HANDLE h = FindFirstFileW(pattern.c_str(), &data);
    if (h == INVALID_HANDLE_VALUE)
      return used;
    do {
      if (std::wcscmp(data.cFileName, L".") && std::wcscmp(data.cFileName, L".."))
        used.insert(invariant_lower(data.cFileName));
    } while (FindNextFileW(h, &data));
    FindClose(h);
    return used;
  }
  void atomic_incoming(std::string_view data) {
    if (exists_path(incoming_path()))
      throw ProtocolError("another approval request is already active");
    atomic_replace(incoming_path(), data, true);
  }
  Handle open_preview(const PlistValue::Object &ask, std::string_view token) {
    const auto icon = ask.find("FileIcon");
    if (icon == ask.end()) {
      log("preview: no FileIcon");
      return {};
    }
    const auto *bytes = std::get_if<Bytes>(&icon->second.value);
    if (!bytes || bytes->empty() || bytes->size() > MaxAskBody) {
      log("preview: unusable FileIcon");
      return {};
    }
    try {
      Handle file(CreateFileW(
          preview_path(token).c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr,
          CREATE_NEW, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE | FILE_FLAG_OPEN_REPARSE_POINT,
          nullptr));
      if (file) {
        write_file(file.get(), *bytes);
        log("preview: available (" + std::to_string(bytes->size()) + " bytes)");
      } else {
        log("preview: file could not be created");
      }
      return file;
    } catch (const std::exception &) {
      log("preview: file could not be written");
      return {};
    }
  }
  void approve_request(Connection &c, std::span<const std::uint8_t> body) {
    BinaryPlist plist(body);
    const auto &root = std::get<PlistValue::Object>(plist.root().value);
    auto fi = root.find("Files");
    if (fi == root.end())
      throw ProtocolError("only bounded file transfers are supported");
    auto *files = std::get_if<PlistValue::Array>(&fi->second.value);
    if (!files || files->empty() || files->size() > offer::MaxFiles)
      throw ProtocolError("only bounded file transfers are supported");
    std::string transfer;
    auto ti = root.find("TransferID");
    if (ti != root.end()) {
      const PlistValue *v = &ti->second;
      if (auto *o = std::get_if<PlistValue::Object>(&v->value)) {
        auto i = o->find("id");
        v = i == o->end() ? nullptr : &i->second;
      }
      if (v) {
        auto *s = std::get_if<std::string>(&v->value);
        if (!s || s->empty() || s->size() > 128 ||
            std::any_of(s->begin(), s->end(), [](unsigned char ch) { return ch > 0x7f; }))
          throw ProtocolError("invalid TransferID");
        transfer = *s;
      }
    }
    auto used = existing_names();
    std::vector<RequestedFile> requested;
    std::uint64_t total = 0;
    for (const auto &item : *files) {
      auto *o = std::get_if<PlistValue::Object>(&item.value);
      if (!o)
        throw ProtocolError("invalid Ask file metadata");
      auto ni = o->find("FileName");
      if (ni == o->end())
        throw ProtocolError("invalid Ask file metadata");
      auto raw = plist_text(&ni->second, "FileName");
      if (utf8_wide(raw).size() > 1024)
        throw ProtocolError("directories or oversized names are not supported");
      auto di = o->find("FileIsDirectory");
      if (di != o->end()) {
        auto *b = std::get_if<bool>(&di->second.value);
        if (!b || *b)
          throw ProtocolError("directories are not supported");
      }
      auto si = o->find("FileSize");
      auto size = plist_size(si == o->end() ? nullptr : &si->second);
      if (size) {
        if (*size > MaxFileBytes)
          throw ProtocolError("invalid file size");
        if (*size > MaxFileBytes - total)
          throw TooLarge("total file bytes exceed limit");
        total += *size;
      }
      auto name = safe_filename(raw);
      std::string folder;
      if (const auto bi = o->find("FileBomPath"); bi != o->end()) {
        auto path = archive_path(plist_text(&bi->second, "FileBomPath"));
        if (path.name != name)
          throw ProtocolError("archive path does not match approved filename");
        folder = std::move(path.folder);
      }
      RequestedFile f{name, unique_name(name, used), std::move(folder), size};
      requested.push_back(std::move(f));
    }
    ULARGE_INTEGER free{};
    if (!GetDiskFreeSpaceExW(destination_.c_str(), nullptr, &free, nullptr))
      native_error("Check destination free space");
    if (total > (UINT64_MAX - 64 * 1024 * 1024) / 3 || free.QuadPart < total * 3 + 64 * 1024 * 1024)
      throw ProtocolError("not enough free disk space");
    if (pending_) {
      respond(c, 403, {}, c.closeAfterResponse);
      return;
    }
    Approval a;
    a.token = new_token();
    a.sender = "nearby device";
    auto si = root.find("SenderComputerName");
    if (si != root.end())
      try {
        a.sender = safe_display(plist_text(&si->second, "SenderComputerName"), 128);
      } catch (...) {
        a.sender = "nearby device";
      }
    a.transferId = std::move(transfer);
    a.files = std::move(requested);
    a.expires = Clock::now() + AskTimeout;
    const auto display = status_json_files(a.files, true);
    auto incoming = '{' + json_escape(receive_state::TokenField) + ':' + json_escape(a.token) +
                    state_field(receive_state::SenderField) + json_escape(a.sender) +
                    state_field(receive_state::FilesField) + display;
    auto preview = open_preview(root, a.token);
    if (preview)
      incoming += state_field(offer::HasPreviewField) + "true";
    incoming += '}';
    atomic_incoming(incoming);
    log_offer_event(c.id, "published");
    pending_ = a;
    preview_ = std::move(preview);
    c.phase = "approval";
    c.pendingToken = a.token;
    lastResult_.reset();
    write_state(Phase::ApprovalPending, state_field(receive_state::TokenField) + json_escape(a.token) +
                state_field(receive_state::SenderField) + json_escape(a.sender) +
                state_field(receive_state::FilesField) + display +
                state_field(receive_state::ExpiresAtUtcField) + json_escape(utc_after(AskTimeout)));
  }
  void respond(Connection &c, unsigned status, std::span<const std::uint8_t> body = {}, bool close = false) {
    auto id = c.id;
    auto text = http_response(status, body, close);
    emit_data(id, text);
    if (close)
      close_conn(id);
  }
  void fail_approval(const Approval &a, std::string_view diagnostic) {
    write_failure(FailureReason::Other, diagnostic, a.token);
  }
  void fail(Connection &c, unsigned status, std::string_view diagnostic, bool close,
            FailureReason reason = FailureReason::Other) {
    log("request rejected (" + std::to_string(status) + "): " + std::string(diagnostic.substr(0, 160)));
    if (c.upload) {
      auto token = c.upload->approval.token;
      discard_upload(c);
      write_failure(reason, diagnostic, token);
    }
    if (c.phase == "approval")
      drop_pending(c, receive_state::FailedResult);
    respond(c, status, {}, close);
  }
  std::filesystem::path create_stage() {
    if (!sessionStage_.empty())
      return sessionStage_;
    for (unsigned attempt = 0; attempt < 8; ++attempt) {
      GUID g{};
      if (FAILED(CoCreateGuid(&g)))
        native_error("Create staging ID");
      wchar_t id[40]{};
      StringFromGUID2(g, id, 40);
      auto path = destination_ / (L".awdlwin-receive-" + std::wstring(id).substr(1, 36));
      if (CreateDirectoryW(path.c_str(), nullptr)) {
        SetFileAttributesW(path.c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_DIRECTORY);
        return path;
      }
      if (GetLastError() != ERROR_ALREADY_EXISTS)
        native_error("Create receive staging directory");
    }
    throw NativeError("Unable to create receive staging directory");
  }
  bool begin_upload(Connection &c) {
    auto &r = *c.request;
    auto approval = c.approval;
    auto ti = r.headers.find("transferid");
    auto transfer = ti == r.headers.end() ? std::string{} : ti->second;
    if (!approval || Clock::now() > approval->expires) {
      if (approval) {
        c.approval.reset();
        lastResult_ = receive_state::ExpiredResult;
        write_state(Phase::Listening, state_field(receive_state::LastResultField) + json_escape(*lastResult_) +
                    state_field(receive_state::TokenField) + json_escape(approval->token));
      }
      respond(c, 403, {}, true);
      return false;
    }
    if (!transfer.empty() && !approval->transferId.empty() && transfer != approval->transferId) {
      c.approval.reset();
      fail_approval(*approval, "TransferID mismatch");
      respond(c, 403, {}, true);
      return false;
    }
    auto ci = r.headers.find("content-type");
    auto content = ci == r.headers.end() ? std::string("application/x-cpio") : ci->second;
    auto semi = content.find(';');
    auto media = lower_ascii(trim_ows(std::string_view(content).substr(0, semi)));
    if (media != "application/x-cpio" && media != "application/x-dvzip" &&
        media != "application/octet-stream" && media != "application/gzip") {
      c.approval.reset();
      fail_approval(*approval, "unsupported archive content type");
      respond(c, 400, {}, true);
      return false;
    }
    std::optional<std::uint64_t> totalWire;
    auto tw = r.headers.find("totalbytes");
    if (tw != r.headers.end())
      totalWire = parse_uint(tw->second, MaxArchiveBytes, "TotalBytes");
    auto ei = r.headers.find("expect");
    auto expect = ei == r.headers.end() ? std::string{} : lower_ascii(ei->second);
    if (!expect.empty() && expect != "100-continue") {
      respond(c, 400, {}, true);
      return false;
    }
    Upload upload;
    upload.stage = create_stage();
    upload.rawPath = upload.stage / L"upload.body";
    upload.raw = CreateFileW(upload.rawPath.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                             FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (upload.raw == INVALID_HANDLE_VALUE) {
      if (sessionStage_.empty())
        RemoveDirectoryW(upload.stage.c_str());
      native_error("Create upload spool");
    }
    upload.approval = *approval;
    upload.contentType = std::move(media);
    upload.totalWire = totalWire;
    upload.bodyStart = upload.lastProgress = upload.lastData = Clock::now();
    upload.owned.push_back(upload.rawPath);
    c.approval.reset();
    c.upload = std::move(upload);
    c.phase = "body";
    write_receiving(*approval, 0, totalWire);
    if (expect == "100-continue")
      emit_data(c.id, "HTTP/1.1 100 Continue\r\n\r\n");
    return true;
  }
  bool consume_chunked_memory(Connection &c, std::size_t limit) {
    for (;;) {
      if (c.chunkState == "size") {
        auto end = c.buffer.find("\r\n");
        if (end == std::string::npos) {
          if (c.buffer.size() > MaxHttpChunkLine)
            throw ProtocolError("chunk header exceeds limit");
          return false;
        }
        auto line = std::string(c.buffer.data(), end);
        c.buffer.erase(0, end + 2);
        auto semi = line.find(';');
        auto token = std::string_view(line).substr(0, semi);
        if (token.empty() || !std::all_of(token.begin(), token.end(), [](unsigned char ch) {
              return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F');
            }))
          throw ProtocolError("invalid chunk size");
        std::uint64_t n = 0;
        auto result = std::from_chars(token.data(), token.data() + token.size(), n, 16);
        if (result.ec != std::errc{} || result.ptr != token.data() + token.size())
          throw ProtocolError("invalid chunk size");
        if (n > limit - c.body.size())
          throw TooLarge("metadata body exceeds limit");
        c.chunkRemaining = n;
        c.chunkState = n ? "data" : "trailers";
        continue;
      }
      if (c.chunkState == "data") {
        auto n = static_cast<std::size_t>(
            (std::min)(c.chunkRemaining, static_cast<std::uint64_t>(c.buffer.size())));
        c.body.insert(c.body.end(), c.buffer.begin(), c.buffer.begin() + static_cast<std::ptrdiff_t>(n));
        c.buffer.erase(0, n);
        c.chunkRemaining -= n;
        if (c.chunkRemaining)
          return false;
        c.chunkState = "data-crlf";
        continue;
      }
      if (c.chunkState == "data-crlf") {
        if (c.buffer.size() < 2)
          return false;
        if (c.buffer.compare(0, 2, "\r\n") != 0)
          throw ProtocolError("invalid chunk terminator");
        c.buffer.erase(0, 2);
        c.chunkState = "size";
        continue;
      }
      if (c.chunkState == "trailers") {
        auto end = c.buffer.find("\r\n");
        if (end == std::string::npos) {
          if (c.trailerBytes + c.buffer.size() > MaxHttpTrailers)
            throw TooLarge("HTTP trailers exceed limit");
          return false;
        }
        auto line = std::string(c.buffer.data(), end);
        c.buffer.erase(0, end + 2);
        c.trailerBytes += end + 2;
        if (c.trailerBytes > MaxHttpTrailers)
          throw TooLarge("HTTP trailers exceed limit");
        if (line.empty()) {
          c.chunkState = "size";
          return true;
        }
        if (line.find(':') == std::string::npos)
          throw ProtocolError("malformed HTTP trailer");
        continue;
      }
      throw ProtocolError("invalid chunk parser state");
    }
  }
  bool consume_metadata(std::uint32_t id) {
    auto it = connections_.find(id);
    if (it == connections_.end())
      return false;
    auto &c = it->second;
    auto &r = *c.request;
    const auto limit = r.path == "/Ask" ? MaxAskBody : MaxMetadata;
    if (!r.chunked) {
      auto take = static_cast<std::size_t>(
          (std::min)(r.length - c.body.size(), static_cast<std::uint64_t>(c.buffer.size())));
      c.body.insert(c.body.end(), c.buffer.begin(), c.buffer.begin() + static_cast<std::ptrdiff_t>(take));
      c.buffer.erase(0, take);
      if (c.body.size() < r.length)
        return false;
    } else if (!consume_chunked_memory(c, limit))
      return false;
    if (r.path == "/Discover") {
      auto body = make_plist_response(receiverName_, true);
      respond(c, 200, body, c.closeAfterResponse);
      log_offer_event(id, "discover_answered");
      publish_discovery_notice();
    } else
      approve_request(c, c.body);
    auto live = connections_.find(id);
    if (live == connections_.end())
      return false;
    auto &current = live->second;
    if (current.phase == "approval") {
      current.request.reset();
      current.body.clear();
      if (!current.buffer.empty()) {
        close_conn(id);
        return false;
      }
      return false;
    }
    current.request.reset();
    current.body.clear();
    current.phase = "headers";
    return true;
  }
  void write_receiving(const Approval& approval, std::uint64_t received, std::optional<std::uint64_t> total,
                       bool waitingForData = false) {
    write_state(Phase::Receiving, state_field(receive_state::TokenField) + json_escape(approval.token) +
                state_field(receive_state::SenderField) + json_escape(approval.sender) +
                state_field(receive_state::ReceivedBytesField) + std::to_string(received) +
                state_field(receive_state::TotalBytesField) + (total ? std::to_string(*total) : "null") +
                state_field(receive_state::TotalFilesField) + std::to_string(approval.files.size()) +
                state_field(receive_state::WaitingForDataField) + (waitingForData ? "true" : "false"));
  }
  void publish_upload_progress(Upload &upload, Clock::time_point now, bool waitingForData) {
    write_receiving(upload.approval, upload.received, upload.totalWire, waitingForData);
    upload.lastProgress = now;
    upload.reportedBytes = upload.received;
    upload.waitingForData = waitingForData;
  }
  void write_upload(Connection &c, std::span<const std::uint8_t> data) {
    auto &u = *c.upload;
    if (data.size() > MaxArchiveBytes - u.received)
      throw TooLarge("upload exceeds archive limit");
    const auto size = data.size();
    if (u.received < u.prefix.size()) {
      const auto prefixSize = static_cast<std::size_t>(u.received);
      const auto added = (std::min)(data.size(), u.prefix.size() - prefixSize);
      std::copy_n(data.begin(), added, u.prefix.begin() + prefixSize);
      data = data.subspan(added);
      if (prefixSize + added == u.prefix.size()) {
        const auto bits = archive_window_bits(u.contentType, u.prefix);
        if (bits || u.contentType == "application/x-dvzip") {
          const auto decodedPath = u.stage / L"decoded.cpio";
          Handle decoded(CreateFileW(decodedPath.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                                     CREATE_NEW, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
          if (!decoded)
            native_error("Create CPIO staging file");
          u.owned.push_back(decodedPath);
          u.decoder = std::make_unique<ArchiveDecoder>(std::move(decoded), bits);
          u.decoder->append(u.prefix, [this] { check_cancel(); });
        } else {
          write_file(u.raw, u.prefix);
        }
      }
    }
    if (u.decoder)
      u.decoder->append(data, [this] { check_cancel(); });
    else
      write_file(u.raw, data);
    u.received += size;
    u.lastData = Clock::now();
    if (u.waitingForData || u.lastData - u.lastProgress >= StateWriteInterval)
      publish_upload_progress(u, u.lastData, false);
  }
  bool consume_chunked_upload(Connection &c) {
    for (;;) {
      if (c.chunkState == "size") {
        auto end = c.buffer.find("\r\n");
        if (end == std::string::npos) {
          if (c.buffer.size() > MaxHttpChunkLine)
            throw ProtocolError("chunk header exceeds limit");
          return false;
        }
        auto line = std::string(c.buffer.data(), end);
        c.buffer.erase(0, end + 2);
        auto semi = line.find(';');
        auto token = std::string_view(line).substr(0, semi);
        if (token.empty() || !std::all_of(token.begin(), token.end(), [](unsigned char ch) {
              return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F');
            }))
          throw ProtocolError("invalid upload chunk size");
        std::uint64_t n = 0;
        auto res = std::from_chars(token.data(), token.data() + token.size(), n, 16);
        if (res.ec != std::errc{} || res.ptr != token.data() + token.size())
          throw ProtocolError("invalid upload chunk size");
        if (n > MaxArchiveBytes - c.upload->received)
          throw TooLarge("upload exceeds archive limit");
        c.chunkRemaining = n;
        c.chunkState = n ? "data" : "trailers";
        continue;
      }
      if (c.chunkState == "data") {
        auto take = static_cast<std::size_t>(
            (std::min)(c.chunkRemaining, static_cast<std::uint64_t>(c.buffer.size())));
        if (take) {
          write_upload(c, std::span(reinterpret_cast<const std::uint8_t *>(c.buffer.data()), take));
          c.buffer.erase(0, take);
          c.chunkRemaining -= take;
        }
        if (c.chunkRemaining)
          return false;
        c.chunkState = "data-crlf";
        continue;
      }
      if (c.chunkState == "data-crlf") {
        if (c.buffer.size() < 2)
          return false;
        if (c.buffer.compare(0, 2, "\r\n") != 0)
          throw ProtocolError("invalid upload chunk terminator");
        c.buffer.erase(0, 2);
        c.chunkState = "size";
        continue;
      }
      if (c.chunkState == "trailers") {
        auto end = c.buffer.find("\r\n");
        if (end == std::string::npos) {
          if (c.trailerBytes + c.buffer.size() > MaxHttpTrailers)
            throw TooLarge("HTTP trailers exceed limit");
          return false;
        }
        auto line = std::string(c.buffer.data(), end);
        c.buffer.erase(0, end + 2);
        c.trailerBytes += end + 2;
        if (c.trailerBytes > MaxHttpTrailers)
          throw TooLarge("HTTP trailers exceed limit");
        if (line.empty())
          return true;
        if (line.find(':') == std::string::npos)
          throw ProtocolError("malformed HTTP trailer");
        continue;
      }
      throw ProtocolError("invalid chunk parser state");
    }
  }
  bool consume_upload(Connection &c) {
    auto &r = *c.request;
    auto &u = *c.upload;
    if (!r.chunked) {
      if (r.length > MaxArchiveBytes)
        throw TooLarge("upload exceeds archive limit");
      auto take = static_cast<std::size_t>(
          (std::min)(r.length - u.received, static_cast<std::uint64_t>(c.buffer.size())));
      if (take) {
        write_upload(c, std::span(reinterpret_cast<const std::uint8_t *>(c.buffer.data()), take));
        c.buffer.erase(0, take);
      }
      if (u.received < r.length)
        return false;
    } else if (!consume_chunked_upload(c))
      return false;
    finish_upload(c);
    return true;
  }
  void mark_motw(const std::filesystem::path &path) {
    auto stream = path.wstring() + L":Zone.Identifier";
    Handle f(CreateFileW(stream.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                         FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    if (!f)
      return;
    constexpr char tag[] = "[ZoneTransfer]\r\nZoneId=3\r\n";
    DWORD n = 0;
    WriteFile(f.get(), tag, sizeof(tag) - 1, &n, nullptr);
  }
  enum class UploadEnd { Framed, MissingFinalChunk, PeerClosed };
  void finish_upload(Connection &c, UploadEnd end = UploadEnd::Framed) {
    auto &u = *c.upload;
    auto lastProgress = Clock::now();
    const auto progress = [&] {
      check_cancel();
      const auto now = Clock::now();
      if (now - lastProgress >= std::chrono::seconds(2)) {
        emit(tx10ub::receive_worker_protocol::FinalizingProgress, c.id);
        lastProgress = now;
      }
    };
    if (u.decoder && !u.decoder->at_archive_boundary())
      throw ProtocolError("truncated compressed archive");
    const auto decoded = u.decoder ? u.decoder->output() : u.raw;
    std::vector<std::pair<std::filesystem::path, std::pair<std::string, std::uint64_t>>> outputs;
    try {
      seek_start(decoded);
      outputs = parse_cpio(decoded, u.approval.files, u.stage, progress, u.owned);
    } catch (...) {
      for (auto i = u.owned.begin(); i != u.owned.end();) {
        if (i->extension() == L".part") {
          DeleteFileW(i->c_str());
          i = u.owned.erase(i);
        } else
          ++i;
      }
      throw;
    }
    u.decoder.reset();
    if (outputs.empty())
      throw ProtocolError("empty file transfer");
    auto reserved = existing_names();
    u.published.clear();
    if (u.raw != INVALID_HANDLE_VALUE) {
      CloseHandle(u.raw);
      u.raw = INVALID_HANDLE_VALUE;
    }
    for (const auto &entry : outputs) {
      progress();
      auto name = unique_name(entry.second.first, reserved);
      for (;;) {
        progress();
        auto source = entry.first;
        auto target = destination_ / utf8_wide(name);
        mark_motw(source);
        if (MoveFileExW(source.c_str(), target.c_str(), MOVEFILE_WRITE_THROUGH)) {
          u.published.push_back(wide_utf8(target.wstring()));
          savedPaths_.push_back(u.published.back());
          if (savedPaths_.size() > 256) savedPaths_.erase(savedPaths_.begin());
          std::erase(u.owned, source);
          break;
        }
        auto error = GetLastError();
        if (error == ERROR_ALREADY_EXISTS || error == ERROR_FILE_EXISTS) {
          name = unique_name(entry.second.first, reserved);
          continue;
        }
        SetLastError(error);
        native_error("Publish received file", FailureReason::SaveFailed);
      }
    }
    const auto id = c.id;
    const auto saved = u.published;
    // The spool is open at bodyStart. Exclude approval, final-chunk waits and extraction.
    const auto bodyReceiveUs = std::chrono::duration_cast<std::chrono::microseconds>(u.lastData - u.bodyStart).count();
    const auto receivedBytes = u.received;
    const auto token = u.approval.token, sender = u.approval.sender;
    std::vector<std::pair<std::string, std::uint64_t>> files;
    for (std::size_t i = 0; i < saved.size() && i < outputs.size(); ++i)
      files.push_back({wide_utf8(std::filesystem::path(utf8_wide(saved[i])).filename().wstring()),
                       outputs[i].second.second});
    discard_upload(c);
    lastResult_ = receive_state::PhaseName(Phase::Completed);
    auto state = state_field(receive_state::TokenField) + json_escape(token) +
                 state_field(receive_state::SenderField) + json_escape(sender) +
                 state_field(receive_state::ReceivedBytesField) + std::to_string(receivedBytes) +
                 state_field(receive_state::BodyReceiveUsField) + std::to_string(bodyReceiveUs) +
                 state_field(receive_state::FilesField) + '[';
    for (std::size_t i = 0; i < files.size(); ++i) {
      if (i)
        state += ',';
      state += std::string("{\"") + receive_state::FileNameField + "\":" + json_escape(files[i].first) +
               state_field(receive_state::FileSizeField) + std::to_string(files[i].second) + '}';
    }
    state += ']';
    write_state(Phase::Completed, std::move(state));
    // A later transfer gets its own TCP connection. The probe drains the
    // success response and TLS close before reopening discovery.
    if (end != UploadEnd::PeerClosed)
      emit_data(id, http_response(200, {}, true));
    constexpr std::array closeNotice{tx10ub::receive_worker_protocol::UploadCommitted};
    close_conn(id, closeNotice);
  }
  void drive(std::uint32_t id) {
    for (;;) {
      auto live = connections_.find(id);
      if (live == connections_.end())
        return;
      auto &c = live->second;
      if (c.phase == "approval")
        return;
      if (c.phase == "headers") {
        auto marker = c.buffer.find("\r\n\r\n");
        if (marker == std::string::npos) {
          if (c.buffer.size() > MaxHeaders)
            throw TooLarge("HTTP headers exceed limit");
          return;
        }
        auto end = marker + 4;
        if (end > MaxHeaders)
          throw TooLarge("HTTP headers exceed limit");
        auto block = std::string_view(c.buffer).substr(0, end);
        auto request = parse_headers(block);
        c.buffer.erase(0, end);
        c.request = std::move(request);
        c.body.clear();
        c.chunkState = "size";
        c.trailerBytes = 0;
        c.bodyRemaining = c.request->length;
        c.phase = "body";
        auto ci = c.request->headers.find("connection");
        c.closeAfterResponse = c.request->version == "HTTP/1.0" ||
                               (ci != c.request->headers.end() && lower_ascii(ci->second) == "close");
        if (c.request->path == "/Upload") {
          if (!begin_upload(c))
            return;
        } else if (c.request->path != "/Discover" && c.request->path != "/Ask") {
          respond(c, 404, {}, true);
          return;
        } else {
          const auto &r = *c.request;
          if (!r.chunked && r.length > (r.path == "/Ask" ? MaxAskBody : MaxMetadata))
            throw TooLarge("metadata body exceeds limit");
          const auto expect = r.headers.find("expect");
          const bool wantsContinue = r.version == "HTTP/1.1" && expect != r.headers.end() &&
                                     lower_ascii(expect->second) == "100-continue";
          if (wantsContinue && (r.chunked || c.buffer.size() < r.length))
            emit_data(c.id, "HTTP/1.1 100 Continue\r\n\r\n");
          log_offer_event(id, r.path + (wantsContinue ? " headers expect_continue=1" : " headers expect_continue=0"));
        }
      }
      if (!connections_.contains(id))
        return;
      if (c.upload) {
        if (!consume_upload(c))
          return;
        continue;
      }
      if (!consume_metadata(id))
        return;
    }
  }
  void open_conn(std::uint32_t id, std::span<const std::uint8_t> payload) {
    if (!id || connections_.contains(id) || connections_.size() >= MaxConnections) {
      emit(Close, id);
      return;
    }
    std::string peer = "nearby device";
    if (!payload.empty()) {
      if (payload.size() > 4096) {
        emit(Close, id);
        return;
      }
      try {
        std::string raw(reinterpret_cast<const char *>(payload.data()), payload.size());
        (void)utf8_wide(raw);
        auto json = JsonParser(raw).parse();
        if (auto *o = std::get_if<JsonValue::Object>(&json.value)) {
          auto i = o->find("peer");
          if (i == o->end())
            i = o->find("address");
          if (i != o->end()) {
            if (auto *s = std::get_if<std::string>(&i->second.value))
              peer = safe_display(*s, 128);
            else if (auto *n = std::get_if<std::uint64_t>(&i->second.value); n && *n)
              peer = std::to_string(*n);
            else if (auto *b = std::get_if<bool>(&i->second.value); b && *b)
              peer = "True";
          }
        }
      } catch (...) {
        emit(Close, id);
        return;
      }
    }
    Connection c;
    c.id = id;
    c.peer = std::move(peer);
    connections_.emplace(id, std::move(c));
    log_offer_event(id, "connected");
  }
  void handle_data(std::uint32_t id, std::span<const std::uint8_t> payload) {
    auto it = connections_.find(id);
    if (it == connections_.end()) {
      emit(Close, id);
      return;
    }
    if (payload.empty() || payload.size() > MaxFrame) {
      fail(it->second, 400, "invalid data frame", true);
      return;
    }
    if (it->second.phase == "approval") {
      close_conn(id);
      return;
    }
    it->second.buffer.append(reinterpret_cast<const char *>(payload.data()), payload.size());
    try {
      drive(id);
    } catch (const Cancelled &) {
      stop();
    } catch (const TooLarge &e) {
      if (connections_.contains(id))
        fail(connections_.at(id), 413, e.what(), true);
    } catch (const ProtocolError &e) {
      if (connections_.contains(id))
        fail(connections_.at(id), 400, e.what(), true);
    } catch (const std::bad_alloc &) {
      if (connections_.contains(id))
        fail(connections_.at(id), 500, "out of memory", true);
    } catch (const NativeError &e) {
      if (connections_.contains(id))
        fail(connections_.at(id), 500, e.what(), true, e.reason);
    } catch (const std::exception &e) {
      if (connections_.contains(id))
        fail(connections_.at(id), 500, e.what(), true);
    }
  }
  void poll_decision() {
    if (!pending_)
      return;
    auto a = *pending_;
    auto path = control_ / offer::DecisionName(a.token);
    offer::Decision decision;
    if (Clock::now() >= a.expires)
      decision = offer::Decision::Expired;
    else
      try {
        const auto data = read_small_file(path, 32);
        decision = offer::ParseDecision(data);
      } catch (const NotFound &) {
        return;
      } catch (const NativeError &) {
        return;
      } catch (const ProtocolError &) {
        decision = offer::Decision::Invalid;
      }
    auto it = connections_.find(0);
    for (auto i = connections_.begin(); i != connections_.end(); ++i)
      if (i->second.pendingToken && *i->second.pendingToken == a.token) {
        it = i;
        break;
      }
    remove_prompt(a.token);
    pending_.reset();
    if (it == connections_.end())
      return;
    auto &c = it->second;
    if (c.phase != "approval" || c.pendingToken != a.token)
      return;
    c.pendingToken.reset();
    const auto id = c.id;
    const bool closeAfterResponse = c.closeAfterResponse;
    if (decision == offer::Decision::Accept) {
      Approval accepted = a;
      accepted.expires = Clock::now() + UploadTimeout;
      c.approval = accepted;
      c.phase = "headers";
      lastCompletedFields_.reset();
      lastResult_.reset();
      write_receiving(a, 0, std::nullopt);
      auto body = make_plist_response(receiverName_, false);
      respond(c, 200, body, closeAfterResponse);
      if (!closeAfterResponse && connections_.contains(id))
        drive(id);
    } else {
      lastResult_ = decision == offer::Decision::Expired ? receive_state::ExpiredResult :
                    decision == offer::Decision::Reject ? receive_state::RejectedResult : receive_state::FailedResult;
      listening();
      respond(c, 403, {}, true);
    }
  }
  void tick() {
    check_cancel();
    poll_decision();
    const auto now = Clock::now();
    std::vector<std::uint32_t> ids;
    for (auto &[id, c] : connections_)
      ids.push_back(id);
    for (auto id : ids) {
      auto it = connections_.find(id);
      if (it == connections_.end())
        continue;
      auto &c = it->second;
      if (!c.upload) {
        if (c.approval && now >= c.approval->expires) {
          c.approval.reset();
          lastResult_ = receive_state::ExpiredResult;
          listening();
        }
        continue;
      }
      auto &u = *c.upload;
      const auto quiet = now - u.lastData;
      const auto timeout = u.received ? UploadStallTimeout : UploadTimeout;
      if (quiet >= timeout) {
        fail(c, 400, "approved upload timed out", true, FailureReason::UploadTimedOut);
        continue;
      }
      if ((!u.waitingForData && quiet >= UploadWaitingNotice) ||
          (u.received != u.reportedBytes && now - u.lastProgress >= StateWriteInterval))
        publish_upload_progress(u, now, quiet >= UploadWaitingNotice);
      if (!c.request || !c.request->chunked || c.chunkState != "size" || !c.buffer.empty() || !u.received)
        continue;
      const bool exactLength = u.totalWire && *u.totalWire == u.received;
      const auto grace = exactLength ? SizedUploadEndGrace : QuietFinish;
      if (quiet < grace || u.received == u.probedBytes || (u.decoder && !u.decoder->at_archive_boundary()))
        continue;
      u.probedBytes = u.received;
      const bool completeStream = u.decoder && u.decoder->complete_stream();
      // In compatibility mode a late final chunk still belongs to this upload.
      // Close after the response so its bytes cannot become a new HTTP request.
      try {
        const auto decoded = u.decoder ? u.decoder->output() : u.raw;
        if (!completeStream && !has_cpio_trailer(decoded))
          continue;
        finish_upload(c, UploadEnd::MissingFinalChunk);
      } catch (const Cancelled &) {
        stop();
        return;
      } catch (const TooLarge &e) {
        if (connections_.contains(id))
          fail(connections_.at(id), 413, std::string("incomplete upload: ") + e.what(), true);
      } catch (const ProtocolError &e) {
        if (completeStream) {
          fail(c, 400, e.what(), true);
          continue;
        }
        // Validation reads the spool. The next data chunk must append to it.
        try {
          seek_end(u.decoder ? u.decoder->output() : u.raw);
        } catch (const NativeError &error) {
          fail(c, 500, error.what(), true, error.reason);
        }
      } catch (const NativeError &e) {
        if (connections_.contains(id))
          fail(connections_.at(id), 500, std::string("incomplete upload: ") + e.what(), true, e.reason);
      } catch (const std::exception &e) {
        if (connections_.contains(id))
          fail(connections_.at(id), 500, std::string("incomplete upload: ") + e.what(), true);
      }
    }
    if (idleDeadlineMs_ && GetTickCount64() >= *idleDeadlineMs_ && !transfer_active()) {
      const auto cancelPath = control_ / markers::CancelFileName;
      try {
        atomic_replace(cancelPath, markers::IdleTimeoutContent, true);
      } catch (const std::exception &) {
        // A manual stop won the race to publish the same cancellation request.
        if (!exists_path(cancelPath))
          throw;
      }
      idleStopRequested_ = true;
    }
  }
  void handle_close(std::uint32_t id, std::span<const std::uint8_t> payload) {
    const auto it = connections_.find(id);
    if (it == connections_.end())
      return;
    auto &c = it->second;
    const bool peerClosed = payload.size() == 1 &&
                            payload.front() == tx10ub::receive_worker_protocol::OrderlyTlsClose;
    if (peerClosed && c.upload && c.upload->received && c.request && c.request->chunked &&
        c.chunkState == "size" && c.buffer.empty()) {
      // A complete archive may arrive without the final empty HTTP chunk.
      // The existing archive checks must succeed before any files are published.
      try {
        finish_upload(c, UploadEnd::PeerClosed);
        return;
      } catch (const ProtocolError &) {
        // Discard an incomplete archive through the ordinary close path.
      } catch (const NativeError &e) {
        fail(c, 500, e.what(), true, e.reason);
        return;
      }
    }
    close_conn(id);
  }
  void handle(std::uint8_t kind, std::uint32_t id, std::span<const std::uint8_t> payload) {
    if (idleStopRequested_) {
      // The supervisor owns radio cleanup. Stay alive until the transport stops us.
      if (exists_path(control_ / markers::ReceiveStopFileName))
        throw Cancelled("receive stopped");
      return;
    }
    check_cancel();
    if (kind == Open)
      open_conn(id, payload);
    else if (kind == Data)
      handle_data(id, payload);
    else if (kind == Close) {
      handle_close(id, payload);
    } else if (kind == Tick) {
      if (id || !payload.empty())
        throw ProtocolError("TICK must have connection 0 and no payload");
      tick();
    } else
      throw ProtocolError("unknown worker input frame");
  }

public:
  ReceiveWorker(std::filesystem::path control, std::filesystem::path destination, std::string name,
                const std::filesystem::path &stage)
      : control_(std::move(control)), destination_(resolve_destination(std::move(destination))),
        receiverName_(std::move(name)) {
    if (!stage.empty()) {
      sessionStage_ = resolve_destination(stage);
      if (sessionStage_.parent_path() != destination_ ||
          !sessionStage_.filename().wstring().starts_with(L".awdlwin-receive-"))
        throw NativeError("invalid receive staging directory");
    }
    std::filesystem::create_directories(control_);
    clear_stale_prompt();
    write_state(Phase::Listening);
  }
  int run() {
    for (;;) {
      std::array<std::uint8_t, 9> h{};
      DWORD first = 0;
      if (!ReadFile(in_, h.data(), static_cast<DWORD>(h.size()), &first, nullptr)) {
        if (GetLastError() == ERROR_BROKEN_PIPE)
          break;
        abort_all("worker input read failed");
        return 2;
      }
      if (!first)
        break;
      while (first < h.size()) {
        DWORD n = 0;
        if (!ReadFile(in_, h.data() + first, static_cast<DWORD>(h.size() - first), &n, nullptr) || !n) {
          abort_all("truncated input frame header");
          return 2;
        }
        first += n;
      }
      std::uint32_t id = 0, length = 0;
      for (unsigned i = 0; i < 4; ++i) {
        id |= std::uint32_t(h[1 + i]) << (8 * i);
        length |= std::uint32_t(h[5 + i]) << (8 * i);
      }
      if (length > MaxFrame) {
        abort_all("input frame exceeds limit");
        return 2;
      }
      Bytes payload(length);
      if (length && !exact_io(in_, payload.data(), length, false)) {
        abort_all("truncated input frame payload");
        return 2;
      }
      try {
        handle(h[0], id, payload);
      } catch (const Cancelled &) {
        stop();
        break;
      } catch (const NativeError &e) {
        log(std::string("worker frame failure: ") + e.what());
        abort_all(typeid(e).name(), e.reason);
        return 2;
      } catch (const std::exception &e) {
        log(std::string("worker frame failure: ") + e.what());
        abort_all(typeid(e).name());
        return 2;
      }
    }
    std::vector<std::uint32_t> ids;
    for (const auto &[id, c] : connections_) {
      (void)c;
      ids.push_back(id);
    }
    for (auto id : ids)
      close_conn(id);
    return 0;
  }
};

} // namespace

int wmain(int argc,wchar_t**argv){
 try{std::filesystem::path control,destination,staging;std::optional<std::wstring> name;DWORD ownerPid=0;
  for(int i=1;i<argc;++i){std::wstring_view a=argv[i];if(a==L"--control"&&i+1<argc)control=argv[++i];else if(a==L"--destination"&&i+1<argc)destination=argv[++i];else if(a==L"--staging"&&i+1<argc)staging=argv[++i];else if(a==L"--name"&&i+1<argc)name=argv[++i];else if(a==L"--owner-pid"&&i+1<argc){std::wstring_view value=argv[++i];if(value.empty())return 2;std::uint64_t parsed=0;for(auto ch:value){if(ch<L'0'||ch>L'9')return 2;const auto digit=static_cast<unsigned>(ch-L'0');if(parsed>(MAXDWORD-digit)/10)return 2;parsed=parsed*10+digit;}ownerPid=static_cast<DWORD>(parsed);}else return 2;}
  if(control.empty()||destination.empty())return 2;
  const auto computerName = name ? std::wstring{} : tx10ub::ReadLocalComputerName();
  if (!name && computerName.empty()) throw NativeError("Windows computer name lookup failed");
  const auto receiverName = name ? safe_display(wide_utf8(*name), 40) : safe_display(wide_utf8(computerName));
  tx10ub::ScopedUserFileAccess fileAccess(ownerPid);
  ReceiveWorker worker(control,destination,receiverName,staging);
  return worker.run();
 }catch(const std::exception&e){std::string s="receive-worker: fatal ";s+=e.what();s+="\r\n";DWORD n=0;WriteFile(GetStdHandle(STD_ERROR_HANDLE),s.data(),static_cast<DWORD>(s.size()),&n,nullptr);return 2;}
}

