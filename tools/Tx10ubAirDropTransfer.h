#pragma once
#include "Tx10ubProbeEvents.h"
#include "Tx10ubAirDropHttp.h"
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include "Tx10ubSendFiles.h"
#include <algorithm>
#include <array>
#include <charconv>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace tx10ub::airdrop {
using Bytes=awdlwin::wire::Bytes;
// Each regular file is held open read-only through upload. No directory,
// symlink traversal or archive extraction is implemented by this sender.
struct File {
    std::u16string name;
    std::string archiveName,type;
    std::uint64_t size=0,modifiedSeconds=0,cpioBytes=0,archiveBytes=0;
    HANDLE handle=INVALID_HANDLE_VALUE;
    File()=default;
    File(const File&)=delete;
    File& operator=(const File&)=delete;
    File(File&& other)noexcept { *this=std::move(other); }
    File& operator=(File&& other)noexcept {
        if(this!=&other) {
            close();name=std::move(other.name);archiveName=std::move(other.archiveName);
            type=std::move(other.type);size=other.size;modifiedSeconds=other.modifiedSeconds;
            cpioBytes=other.cpioBytes;archiveBytes=other.archiveBytes;
            handle=std::exchange(other.handle,INVALID_HANDLE_VALUE);
        }
        return *this;
    }
    ~File(){close();}
    void close()noexcept {if(handle!=INVALID_HANDLE_VALUE){CloseHandle(handle);handle=INVALID_HANDLE_VALUE;}}
    bool holds_source()const noexcept{return handle!=INVALID_HANDLE_VALUE;}
};
struct SendBatch {
    std::vector<File> files;
    std::uint64_t size = 0;
};
namespace detail {
inline bool valid_transfer_id(std::string_view id) {
    if(id.size()!=36)return false;
    for(std::size_t i=0;i<id.size();++i) {
        if(i==8||i==13||i==18||i==23){if(id[i]!='-')return false;}
        else if(!((id[i]>='0'&&id[i]<='9')||(id[i]>='A'&&id[i]<='F')))return false;
    }
    return true;
}
inline void big(Bytes& out,std::uint64_t n,unsigned width) {
    for(unsigned i=width;i;--i)out.push_back(static_cast<std::uint8_t>(n>>((i-1)*8)));
}
// Restricted binary-plist writer: strings, bool/int, array and dictionary only.
// Keep one-byte references for single-file requests; batches use two bytes.
class Plist {
    std::vector<Bytes> objects_;
    unsigned refSize_;
    static void count(Bytes& b,std::uint8_t marker,std::size_t n) {
        b.push_back(static_cast<std::uint8_t>(marker|(n<15?n:15)));
        if(n>=15){b.push_back(0x12);big(b,n,4);}
    }
    std::uint16_t add(Bytes b) {
        if(objects_.size()>=(refSize_==1?255u:65535u))throw std::length_error("Ask plist object limit");
        objects_.push_back(std::move(b));return static_cast<std::uint16_t>(objects_.size()-1);
    }
public:
    explicit Plist(bool multiple=false):refSize_(multiple?2u:1u){}
    std::uint16_t text(std::u16string_view s) {
        Bytes b;count(b,0x60,s.size());for(auto c:s)big(b,c,2);return add(std::move(b));
    }
    std::uint16_t ascii(std::string_view s) {
        Bytes b;count(b,0x50,s.size());b.insert(b.end(),s.begin(),s.end());return add(std::move(b));
    }
    std::uint16_t boolean(bool value){return add({static_cast<std::uint8_t>(value?9:8)});}
    std::uint16_t zero(){return add({0x10,0});}
    std::uint16_t array(std::span<const std::uint16_t> refs) {
        Bytes b;count(b,0xa0,refs.size());for(auto ref:refs)big(b,ref,refSize_);return add(std::move(b));
    }
    std::uint16_t dict(std::initializer_list<std::pair<std::string_view,std::uint16_t>> items) {
        Bytes b;count(b,0xd0,items.size());
        for(const auto& item:items)big(b,ascii(item.first),refSize_);
        for(const auto& item:items)big(b,item.second,refSize_);return add(std::move(b));
    }
    Bytes finish(std::uint16_t root)const {
        Bytes b{'b','p','l','i','s','t','0','0'};std::vector<std::size_t> offsets;
        for(const auto& object:objects_){offsets.push_back(b.size());b.insert(b.end(),object.begin(),object.end());}
        const auto table=b.size();for(auto offset:offsets)big(b,offset,4);
        b.insert(b.end(),6,0);b.insert(b.end(),{4,static_cast<std::uint8_t>(refSize_)});
        big(b,objects_.size(),8);big(b,root,8);big(b,table,8);return b;
    }
};
inline void octal(std::array<std::uint8_t,76>& h,std::size_t at,unsigned width,std::uint64_t value) {
    for(unsigned i=width;i;--i){h[at+i-1]=static_cast<std::uint8_t>('0'+(value&7));value>>=3;}
    if(value)throw std::length_error("POSIX odc CPIO field overflow");
}
inline std::array<std::uint8_t,76> odc_header(std::string_view name,std::uint64_t size,
                                              std::uint64_t modifiedSeconds,bool trailer=false,std::uint64_t inode=1) {
    constexpr std::uint64_t maximumOdcValue=0x1ffffffffULL; // eleven octal digits
    constexpr std::uint64_t maximumOdcName=0x3ffffULL; // six octal digits
    if(size>maximumOdcValue||modifiedSeconds>maximumOdcValue||name.size()+1>maximumOdcName)
        throw std::length_error("File cannot be represented in POSIX odc CPIO");
    std::array<std::uint8_t,76> h{};std::fill(h.begin(),h.end(),static_cast<std::uint8_t>('0'));
    std::copy_n("070707",6,h.begin());
    octal(h,12,6,trailer?0:inode);octal(h,18,6,trailer?0:0100644);octal(h,36,6,trailer?0:1);
    octal(h,48,11,trailer?0:modifiedSeconds);octal(h,59,6,name.size()+1);octal(h,65,11,trailer?0:size);
    return h;
}
inline std::uint32_t crc_update(std::uint32_t crc,std::span<const std::uint8_t> data) {
    static constexpr auto table=[] {
        std::array<std::uint32_t,256> values{};
        for(std::uint32_t i=0;i<values.size();++i) {
            auto n=i;for(unsigned bit=0;bit<8;++bit)n=(n>>1)^(0xedb88320u&(0u-(n&1u)));
            values[i]=n;
        }
        return values;
    }();
    for(auto byte:data)crc=table[(crc^byte)&0xff]^(crc>>8);return crc;
}
inline std::uint64_t gzip_size(std::uint64_t cpioSize) {
    const auto blocks=cpioSize/65535+(cpioSize%65535?1:0);
    if(blocks>(UINT64_MAX-cpioSize-18)/5)throw std::length_error("AirDrop archive size overflow");
    return cpioSize+blocks*5+18;
}
inline constexpr std::uint64_t TrailerBytes=76+sizeof("TRAILER!!!");
inline std::uint64_t cpio_size(std::span<const File> files) {
    auto size=TrailerBytes;
    for(const auto& file:files)size+=76+file.archiveName.size()+1+file.size;
    return size;
}
inline void windows_error(const char* operation) {
    throw std::system_error(static_cast<int>(GetLastError()),std::system_category(),operation);
}
inline void seek_start(HANDLE file) {
    LARGE_INTEGER zero{};if(!SetFilePointerEx(file,zero,nullptr,FILE_BEGIN))windows_error("Seek AirDrop source");
}
inline std::size_t read_some(HANDLE file,std::span<std::uint8_t> output) {
    if(output.empty())return 0;
    const auto count=static_cast<DWORD>((std::min)(output.size(),static_cast<std::size_t>(MAXDWORD)));
    DWORD received=0;if(!ReadFile(file,output.data(),count,&received,nullptr))windows_error("Read AirDrop source");
    return received;
}
} // namespace detail

// Reads the CPIO source and emits one gzip stream using stored DEFLATE blocks.
// Only the caller's small output buffer is used regardless of source size.
class ArchiveStream {
    enum class Phase {gzipHeader,deflate,gzipTrailer,done};
    enum class CpioPart {fileHeader,fileName,fileData,trailerHeader,trailerName,done};
    std::span<const File> files_;
    std::size_t fileIndex_=0;
    Phase phase_=Phase::gzipHeader;
    CpioPart cpioPart_=CpioPart::fileHeader;
    const std::array<std::uint8_t,10> gzipHeader_{0x1f,0x8b,8,0,0,0,0,0,0,3};
    std::array<std::uint8_t,8> gzipTrailer_{};
    std::size_t fixedOffset_=0,nameOffset_=0;
    std::array<std::uint8_t,76> fileHeader_{},trailerHeader_{};
    std::uint64_t fileRemaining_=0,fileBytesRead_=0,cpioSize_,archiveSize_,cpioRemaining_;
    std::uint16_t blockRemaining_=0;
    std::array<std::uint8_t,5> blockHeader_{};
    std::size_t blockHeaderOffset_=0;
    bool blockHeaderPending_=false;
    std::uint32_t crc_=0xffffffffu;
    std::uint64_t produced_=0;
    void start_entry() {
        if(fileIndex_==files_.size()){cpioPart_=CpioPart::trailerHeader;return;}
        const auto& file=files_[fileIndex_];
        if(!file.holds_source())throw std::logic_error("AirDrop source handle is not open");
        detail::seek_start(file.handle);fileRemaining_=file.size;
        fileHeader_=detail::odc_header(file.archiveName,file.size,file.modifiedSeconds,false,fileIndex_+1);
        cpioPart_=CpioPart::fileHeader;
    }
    std::size_t copy_fixed(std::span<std::uint8_t> output,std::span<const std::uint8_t> input,
                           std::size_t& offset) {
        const auto count=(std::min)(output.size(),input.size()-offset);
        std::copy_n(input.begin()+offset,count,output.begin());offset+=count;return count;
    }
    std::size_t read_cpio(std::span<std::uint8_t> output) {
        std::size_t written=0;
        while(written<output.size()&&cpioPart_!=CpioPart::done) {
            auto remaining=output.subspan(written);std::size_t count=0;
            switch(cpioPart_) {
            case CpioPart::fileHeader:
                count=copy_fixed(remaining,fileHeader_,fixedOffset_);
                if(fixedOffset_==fileHeader_.size()){fixedOffset_=0;cpioPart_=CpioPart::fileName;nameOffset_=0;}
                break;
            case CpioPart::fileName: {
                const auto& name=files_[fileIndex_].archiveName;
                if(nameOffset_<name.size()) {
                    count=(std::min)(remaining.size(),name.size()-nameOffset_);
                    std::copy_n(reinterpret_cast<const std::uint8_t*>(name.data()+nameOffset_),count,remaining.begin());
                    nameOffset_+=count;
                } else {
                    remaining[0]=0;count=1;
                    if(fileRemaining_)cpioPart_=CpioPart::fileData;
                    else {++fileIndex_;start_entry();}
                }
                break;
            }
            case CpioPart::fileData:
                count=detail::read_some(files_[fileIndex_].handle,remaining.first(static_cast<std::size_t>((std::min)(fileRemaining_,static_cast<std::uint64_t>(remaining.size())))));
                if(!count)throw std::runtime_error("AirDrop source ended before its locked file size");
                fileRemaining_-=count;fileBytesRead_+=count;
                if(!fileRemaining_){++fileIndex_;start_entry();}
                break;
            case CpioPart::trailerHeader:
                count=copy_fixed(remaining,trailerHeader_,fixedOffset_);
                if(fixedOffset_==trailerHeader_.size()){fixedOffset_=0;cpioPart_=CpioPart::trailerName;nameOffset_=0;}
                break;
            case CpioPart::trailerName: {
                constexpr std::string_view trailer="TRAILER!!!";
                if(nameOffset_<trailer.size()) {
                    count=(std::min)(remaining.size(),trailer.size()-nameOffset_);
                    std::copy_n(reinterpret_cast<const std::uint8_t*>(trailer.data()+nameOffset_),count,remaining.begin());
                    nameOffset_+=count;
                } else {remaining[0]=0;count=1;cpioPart_=CpioPart::done;}
                break;
            }
            case CpioPart::done:break;
            }
            if(!count)throw std::logic_error("CPIO source made no progress");
            crc_=detail::crc_update(crc_,remaining.first(count));written+=count;
        }
        return written;
    }
public:
    explicit ArchiveStream(std::span<const File> files):files_(files),cpioSize_(detail::cpio_size(files)),
        archiveSize_(detail::gzip_size(cpioSize_)),cpioRemaining_(cpioSize_) {
        if(files.empty())throw std::invalid_argument("No AirDrop source files");
        start_entry();
        trailerHeader_=detail::odc_header("TRAILER!!!",0,0,true);
    }
    explicit ArchiveStream(const File& file):ArchiveStream(std::span<const File>(&file,1)){}
    std::uint64_t size()const noexcept{return archiveSize_;}
    std::uint64_t file_bytes_read()const noexcept{return fileBytesRead_;}
    bool done()const noexcept{return phase_==Phase::done;}
    std::size_t read(std::span<std::uint8_t> output) {
        std::size_t written=0;
        while(written<output.size()&&phase_!=Phase::done) {
            auto remaining=output.subspan(written);std::size_t count=0;
            if(phase_==Phase::gzipHeader) {
                count=copy_fixed(remaining,gzipHeader_,fixedOffset_);written+=count;produced_+=count;
                if(fixedOffset_==gzipHeader_.size()){fixedOffset_=0;phase_=Phase::deflate;}continue;
            }
            if(phase_==Phase::deflate) {
                if(cpioRemaining_==0&&blockRemaining_==0&&!blockHeaderPending_){
                    const auto crc=~crc_;
                    for(unsigned i=0;i<4;++i)gzipTrailer_[i]=static_cast<std::uint8_t>(crc>>(8*i));
                    for(unsigned i=0;i<4;++i)gzipTrailer_[4+i]=static_cast<std::uint8_t>(cpioSize_>>(8*i));
                    phase_=Phase::gzipTrailer;fixedOffset_=0;continue;
                }
                if(blockHeaderPending_) {
                    count=copy_fixed(remaining,blockHeader_,blockHeaderOffset_);written+=count;produced_+=count;
                    if(blockHeaderOffset_==blockHeader_.size()){blockHeaderPending_=false;blockHeaderOffset_=0;}
                    continue;
                }
                if(blockRemaining_==0) {
                    if(!cpioRemaining_)continue;
                    blockRemaining_=static_cast<std::uint16_t>((std::min)(std::uint64_t{65535},cpioRemaining_));
                    const auto final=cpioRemaining_==blockRemaining_;
                    const auto length=blockRemaining_;
                    blockHeader_[0]=final?1:0;blockHeader_[1]=static_cast<std::uint8_t>(length);
                    blockHeader_[2]=static_cast<std::uint8_t>(length>>8);
                    blockHeader_[3]=static_cast<std::uint8_t>(length^0xff);
                    blockHeader_[4]=static_cast<std::uint8_t>((length>>8)^0xff);
                    blockHeaderPending_=true;continue;
                }
                count=read_cpio(remaining.first((std::min)(remaining.size(),static_cast<std::size_t>(blockRemaining_))));
                if(!count)throw std::runtime_error("AirDrop CPIO source ended early");
                cpioRemaining_-=count;blockRemaining_=static_cast<std::uint16_t>(blockRemaining_-count);
                written+=count;produced_+=count;continue;
            }
            if(phase_==Phase::gzipTrailer) {
                count=copy_fixed(remaining,gzipTrailer_,fixedOffset_);written+=count;produced_+=count;
                if(fixedOffset_==gzipTrailer_.size()) {
                    if(produced_!=archiveSize_)throw std::logic_error("AirDrop archive size calculation mismatch");
                    fixedOffset_=0;phase_=Phase::done;
                }
                continue;
            }
        }
        return written;
    }
};

inline File prepare_file(const std::filesystem::path& path) {
    File f;
    f.handle=CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_SEQUENTIAL_SCAN,nullptr);
    if(f.handle==INVALID_HANDLE_VALUE)detail::windows_error("Open AirDrop source read-only");
    BY_HANDLE_FILE_INFORMATION basic{};
    if(!GetFileInformationByHandle(f.handle,&basic))detail::windows_error("Inspect AirDrop source");
    if(GetFileType(f.handle)!=FILE_TYPE_DISK||(basic.dwFileAttributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT)))
        throw std::invalid_argument("AirDrop requires one regular file");
    FILE_STANDARD_INFO standard{};FILE_BASIC_INFO times{};
    if(!GetFileInformationByHandleEx(f.handle,FileStandardInfo,&standard,sizeof(standard))||
       !GetFileInformationByHandleEx(f.handle,FileBasicInfo,&times,sizeof(times)))
        detail::windows_error("Inspect AirDrop source metadata");
    if(standard.Directory||standard.EndOfFile.QuadPart<0)throw std::invalid_argument("AirDrop requires one regular file");
    f.size=static_cast<std::uint64_t>(standard.EndOfFile.QuadPart);
    constexpr std::uint64_t windowsToUnixSeconds=11644473600ULL;
    const auto ticks=times.LastWriteTime.QuadPart;
    if(ticks<0||static_cast<std::uint64_t>(ticks)/10000000ULL<windowsToUnixSeconds)
        throw std::invalid_argument("File modification time cannot be represented in CPIO");
    f.modifiedSeconds=static_cast<std::uint64_t>(ticks)/10000000ULL-windowsToUnixSeconds;
    constexpr std::uint64_t maximumOdcValue=0x1ffffffffULL;
    if(f.size>maximumOdcValue||f.modifiedSeconds>maximumOdcValue)
        throw std::length_error("File cannot be represented in POSIX odc CPIO");
    const auto base=path.filename();f.name=base.u16string();
    const auto utf8=base.u8string();f.archiveName="./"+std::string(utf8.begin(),utf8.end());
    if(f.name.empty()||f.name.size()>255||f.name==u"."||f.name==u".."||f.name==u"TRAILER!!!")
        throw std::invalid_argument("Unsupported AirDrop filename");
    for(std::size_t i=0;i<f.name.size();++i) {
        const auto c=f.name[i];
        if(c<32||c==127||c==u'/'||c==u'\\'||c==u':')throw std::invalid_argument("Unsafe archive filename");
        if(c>=0xd800&&c<=0xdbff) {
            if(++i>=f.name.size()||f.name[i]<0xdc00||f.name[i]>0xdfff)throw std::invalid_argument("Invalid filename Unicode");
        }else if(c>=0xdc00&&c<=0xdfff)throw std::invalid_argument("Invalid filename Unicode");
    }
    const auto header=detail::odc_header(f.archiveName,f.size,f.modifiedSeconds);
    (void)header;
    f.cpioBytes=76+f.archiveName.size()+1+f.size+76+sizeof("TRAILER!!!");
    f.archiveBytes=detail::gzip_size(f.cpioBytes);
    std::array<std::uint8_t,8> prefix{};const auto got=detail::read_some(f.handle,prefix);
    f.type="public.content";
    if(got>=3&&prefix[0]==0xff&&prefix[1]==0xd8&&prefix[2]==0xff)f.type="public.jpeg";
    constexpr std::uint8_t png[]{137,80,78,71,13,10,26,10};
    if(got>=sizeof(png)&&std::equal(std::begin(png),std::end(png),prefix.begin()))f.type="public.png";
    detail::seek_start(f.handle);
    return f;
}

inline SendBatch prepare_files(std::span<const std::filesystem::path> paths) {
    if(paths.empty()||paths.size()>send_files::MaxFiles)throw std::invalid_argument("Invalid AirDrop file count");
    SendBatch batch;
    batch.files.reserve(paths.size());
    for(const auto& path:paths) {
        const auto name=path.filename().wstring();
        if(std::any_of(batch.files.begin(),batch.files.end(),[&](const File& file){
            return send_files::SameFileName(name,std::filesystem::path(file.name).wstring());
        }))throw std::invalid_argument("Duplicate AirDrop filename");
        auto file=prepare_file(path);
        if(file.size>send_files::MaxBytes-batch.size)throw std::length_error("AirDrop files exceed the total size limit");
        batch.size+=file.size;
        batch.files.push_back(std::move(file));
    }
    return batch;
}

inline Bytes ask_body(std::span<const File> files,std::string_view senderId,std::u16string_view senderName,std::string_view transferId) {
    if(!detail::valid_transfer_id(transferId))throw std::invalid_argument("Invalid AirDrop transfer ID");
    detail::Plist p(files.size()>1);
    std::vector<std::uint16_t> entries;
    entries.reserve(files.size());
    for(const auto& f:files) {
        entries.push_back(p.dict({{"FileName",p.text(f.name)},{"FileType",p.ascii(f.type)},
            {"FileBomPath",p.text(std::u16string(u"./")+f.name)},{"FileIsDirectory",p.boolean(false)},
            {"ConvertMediaFormats",p.zero()}}));
    }
    const auto root=p.dict({{"SenderComputerName",p.text(senderName)},{"BundleID",p.ascii("com.apple.finder")},
        {"SenderModelName",p.ascii("Windows")},{"SenderID",p.ascii(senderId)},
        {"ConvertMediaFormats",p.boolean(false)},{"Files",p.array(entries)},
        {"TransferID",p.dict({{"id",p.ascii(transferId)}})},
        {"TransferType",p.dict({{"files",p.dict({})}})}});
    return p.finish(root);
}
inline Bytes ask_body(const File& file,std::string_view senderId,std::u16string_view senderName,std::string_view transferId) {
    return ask_body(std::span<const File>(&file,1),senderId,senderName,transferId);
}
inline Bytes post_request(const awdlwin::ip::Address& address,std::uint16_t port,
                          std::string_view path,std::span<const std::uint8_t> body) {
    std::string host;
    for(std::size_t i=0;i<16;i+=2){if(i)host+=':';char b[4];const auto n=std::to_chars(b,b+4,(unsigned(address[i])<<8)|address[i+1],16);host.append(b,n.ptr);}
    std::string h="POST "+std::string(path)+" HTTP/1.1\r\nHost: ["+host+"]:"+std::to_string(port)+
        "\r\nUser-Agent: AirDrop/1.0\r\nAccept: */*\r\nContent-Type: "+
        "application/octet-stream\r\nConnection: keep-alive\r\nContent-Length: "+std::to_string(body.size())+"\r\n\r\n";
    Bytes out(h.begin(),h.end());out.insert(out.end(),body.begin(),body.end());return out;
}
inline Bytes upload_request_header(const awdlwin::ip::Address& address,std::uint16_t port,
                                  std::uint64_t archiveBytes,std::string_view transferId) {
    if(!detail::valid_transfer_id(transferId))throw std::invalid_argument("Invalid AirDrop transfer ID");
    std::string host;
    for(std::size_t i=0;i<16;i+=2){if(i)host+=':';char b[4];const auto n=std::to_chars(b,b+4,(unsigned(address[i])<<8)|address[i+1],16);host.append(b,n.ptr);}
    const auto h="POST /Upload HTTP/1.1\r\nHost: ["+host+"]:"+std::to_string(port)+
        "\r\nUser-Agent: AirDrop/1.0\r\nAccept: */*\r\nContent-Type: application/x-cpio\r\nTotalBytes: "+
        std::to_string(archiveBytes)+"\r\nTransferID: "+std::string(transferId)+
        "\r\nConnection: keep-alive\r\nTransfer-Encoding: chunked\r\n\r\n";
    return Bytes(h.begin(),h.end());
}
// Exactly one sequential exchange at a time. Upload is unreachable until the
// receiver returns HTTP200 to Ask; denial/failure never retries an upload.
class Exchange {
public:
    enum class Stage {discover,ask,upload};
private:
    std::span<const File> files_;
    std::string senderId_;
    std::u16string senderName_;
    std::string transferId_;
    Stage stage_=Stage::discover;
    bool done_=false;
    bool nextConnection_=false;
    bool uploadTerminatorQueued_=false;
    unsigned status_=0;
    std::unique_ptr<ArchiveStream> archive_;
public:
    Exchange(std::span<const File> files,std::string senderId,std::u16string_view senderName,std::string transferId={})
        :files_(files),senderId_(std::move(senderId)),senderName_(senderName),transferId_(std::move(transferId)) {
        if(!files_.empty()&&!detail::valid_transfer_id(transferId_))throw std::invalid_argument("Invalid AirDrop transfer ID");
    }
    Exchange(const File* file,std::string senderId,std::u16string_view senderName,std::string transferId={})
        :Exchange(file?std::span<const File>(file,1):std::span<const File>{},std::move(senderId),senderName,std::move(transferId)){}
    Stage stage()const{return stage_;}
    const wchar_t* label()const{return stage_ == Stage::discover ? probe_events::WideDiscover.data() :
        stage_ == Stage::ask ? probe_events::WideAsk.data() : probe_events::WideUpload.data();}
    bool done()const{return done_;}
    bool needs_connection()const{return nextConnection_;}
    bool upload_request_queued()const{return uploadTerminatorQueued_;}
    void start_next_connection() {
        if(done_||!nextConnection_)throw std::logic_error("No AirDrop connection transition");
        nextConnection_=false;
    }
    unsigned status()const{return status_;}
    std::uint64_t file_bytes_read()const{return archive_?archive_->file_bytes_read():0;}
    Bytes request(const awdlwin::ip::Address& address,std::uint16_t port) {
        if(done_||nextConnection_)throw std::logic_error("AirDrop connection not ready");
        if(stage_==Stage::discover)return discover_request(address,port,!files_.empty());
        if(stage_==Stage::ask){const auto body=ask_body(files_,senderId_,senderName_,transferId_);return post_request(address,port,"/Ask",body);}
        return upload_request_header(address,port,detail::gzip_size(detail::cpio_size(files_)),transferId_);
    }
    Bytes next_upload_chunk(std::size_t maximumBytes=4096) {
        if(stage_!=Stage::upload||files_.empty()||uploadTerminatorQueued_)
            throw std::logic_error("AirDrop upload stream is not ready");
        if(maximumBytes<16)throw std::invalid_argument("AirDrop upload chunk buffer is too small");
        if(!archive_)archive_=std::make_unique<ArchiveStream>(files_);
        Bytes payload(maximumBytes-8);const auto size=archive_->read(payload);
        if(!size) {
            if(!archive_->done())throw std::runtime_error("AirDrop archive stream ended early");
            uploadTerminatorQueued_=true;return Bytes{'0','\r','\n','\r','\n'};
        }
        payload.resize(size);char count[16];const auto end=std::to_chars(count,count+sizeof(count),size,16);
        Bytes framed;framed.reserve(size+8);framed.insert(framed.end(),count,end.ptr);framed.insert(framed.end(),{'\r','\n'});
        framed.insert(framed.end(),payload.begin(),payload.end());framed.insert(framed.end(),{'\r','\n'});return framed;
    }
    void accept(unsigned status) {
        if(done_||nextConnection_)throw std::logic_error("Unexpected AirDrop response");
        status_=status;
        if(status!=200||files_.empty()||stage_==Stage::upload){done_=true;return;}
        if(stage_==Stage::discover){stage_=Stage::ask;nextConnection_=true;}
        else stage_=Stage::upload;
    }
};
} // namespace tx10ub::airdrop
