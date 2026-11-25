#include "Tx10ubTls.h"
#define SECURITY_WIN32
#include <windows.h>
#include <winternl.h>
#include <security.h>
#define SCHANNEL_USE_BLACKLISTS
#include <schannel.h>
#include <wincrypt.h>
#include <ncrypt.h>
#include <objbase.h>
#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <iostream>
#pragma comment(lib,"secur32.lib")
#pragma comment(lib,"crypt32.lib")
#pragma comment(lib,"ncrypt.lib")
#pragma comment(lib,"ole32.lib")

namespace tx10ub::tls {
using Bytes=awdlwin::wire::Bytes;
namespace {
template<class Generate, class Append>
SECURITY_STATUS generate_close_notify(CtxtHandle& context, Generate generate, Append append) {
    DWORD shutdown = SCHANNEL_SHUTDOWN;
    SecBuffer control{sizeof(shutdown), SECBUFFER_TOKEN, &shutdown};
    SecBufferDesc input{SECBUFFER_VERSION, 1, &control};
    const auto applied = ApplyControlToken(&context, &input);
    if (applied != SEC_E_OK) return applied;
    for (unsigned step = 0; step < 4; ++step) {
        SecBuffer token{0, SECBUFFER_TOKEN, nullptr};
        SecBufferDesc output{SECBUFFER_VERSION, 1, &token};
        const auto status = generate(output);
        struct Token { void* data; ~Token() { if (data) FreeContextBuffer(data); } } owned{token.pvBuffer};
        if (status != SEC_E_OK && status != SEC_I_CONTEXT_EXPIRED && status != SEC_I_CONTINUE_NEEDED)
            return status;
        if (token.cbBuffer && !append(std::span<const std::uint8_t>(
                static_cast<const std::uint8_t*>(token.pvBuffer), token.cbBuffer)))
            return SEC_E_INSUFFICIENT_MEMORY;
        if (status != SEC_I_CONTINUE_NEEDED) return SEC_E_OK;
    }
    return SEC_E_INTERNAL_ERROR;
}
}
struct Identity::Impl {
    NCRYPT_PROV_HANDLE provider=0;
    NCRYPT_KEY_HANDLE key=0;
    PCCERT_CONTEXT cert=nullptr;
    bool release()noexcept {
        if(cert)CertFreeCertificateContext(cert);
        bool ok=true;
        if(key) {
            const auto deleted=NCryptDeleteKey(key,0);
            if(deleted!=ERROR_SUCCESS){NCryptFreeObject(key);ok=false;}
            else std::fputs("tls_temporary_user_key_deleted=1\n",stdout);
        }
        if(provider)NCryptFreeObject(provider);
        cert=nullptr;key=0;provider=0;
        return ok;
    }
    ~Impl(){if(!release())std::fputs("tls_temporary_user_key_delete_failed=1\n",stderr);}
    Impl() {
        try {
            GUID id{};wchar_t text[40]{};
            if(FAILED(CoCreateGuid(&id))||!StringFromGUID2(id,text,40))throw std::runtime_error("TLS identity name failed");
            const auto keyName=std::wstring(L"AWDLWin-TLS-")+text;
            if(NCryptOpenStorageProvider(&provider,MS_KEY_STORAGE_PROVIDER,0)!=0||
               NCryptCreatePersistedKey(provider,&key,NCRYPT_RSA_ALGORITHM,keyName.c_str(),0,0)!=0)
                throw std::runtime_error("temporary TLS user key creation failed");
            // Public identifier only, for exact cleanup if the process crashes.
            // Never log/export the private key. Flush before it is persisted.
            std::wcout<<L"tls_temporary_user_key_name="<<keyName<<L'\n'<<std::flush;
            DWORD bits=2048;
            if(NCryptSetProperty(key,NCRYPT_LENGTH_PROPERTY,reinterpret_cast<PBYTE>(&bits),sizeof(bits),0)!=0||
               NCryptFinalizeKey(key,0)!=0)throw std::runtime_error("TLS key finalization failed");
            DWORD length=0;
            if(!CertStrToNameW(X509_ASN_ENCODING,L"CN=AWDLWin",CERT_X500_NAME_STR,nullptr,nullptr,&length,nullptr))
                throw std::runtime_error("TLS subject encoding failed");
            Bytes subject(length);
            if(!CertStrToNameW(X509_ASN_ENCODING,L"CN=AWDLWin",CERT_X500_NAME_STR,nullptr,subject.data(),&length,nullptr))
                throw std::runtime_error("TLS subject encoding failed");
            CERT_NAME_BLOB name{length,subject.data()};
            CRYPT_ALGORITHM_IDENTIFIER algorithm{const_cast<char*>(szOID_RSA_SHA256RSA),{0,nullptr}};
            SYSTEMTIME end{};GetSystemTime(&end);++end.wYear;
            if(end.wMonth==2&&end.wDay==29)end.wDay=28;
            CRYPT_KEY_PROV_INFO keyInfo{};keyInfo.pwszContainerName=const_cast<wchar_t*>(keyName.c_str());
            keyInfo.pwszProvName=const_cast<wchar_t*>(MS_KEY_STORAGE_PROVIDER);
            // AirDrop uses this identity in both TLS roles. Put the usages in
            // the signed certificate so the peer can verify them.
            LPSTR purposes[]{const_cast<char*>(szOID_PKIX_KP_CLIENT_AUTH),const_cast<char*>(szOID_PKIX_KP_SERVER_AUTH)};
            CERT_ENHKEY_USAGE usage{2,purposes};
            DWORD encodedLength=0;
            if(!CryptEncodeObject(X509_ASN_ENCODING,X509_ENHANCED_KEY_USAGE,&usage,nullptr,&encodedLength))
                throw std::runtime_error("TLS certificate usage size failed");
            Bytes encodedUsage(encodedLength);
            if(!CryptEncodeObject(X509_ASN_ENCODING,X509_ENHANCED_KEY_USAGE,&usage,encodedUsage.data(),&encodedLength))
                throw std::runtime_error("TLS certificate usage encoding failed");
            CERT_EXTENSION extension{const_cast<char*>(szOID_ENHANCED_KEY_USAGE),FALSE,{encodedLength,encodedUsage.data()}};
            CERT_EXTENSIONS extensions{1,&extension};
            cert=CertCreateSelfSignCertificate(key,&name,0,&keyInfo,&algorithm,nullptr,&end,&extensions);
            if(!cert)throw std::runtime_error("TLS certificate creation failed");
            CERT_KEY_CONTEXT context{};context.cbSize=sizeof(context);context.hNCryptKey=key;context.dwKeySpec=CERT_NCRYPT_KEY_SPEC;
            if(!CertSetCertificateContextProperty(cert,CERT_KEY_CONTEXT_PROP_ID,
                CERT_SET_PROPERTY_INHIBIT_PERSIST_FLAG|CERT_STORE_NO_CRYPT_RELEASE_FLAG,&context))
                throw std::runtime_error("TLS key association failed");
        }catch(...){if(!release())std::fputs("tls_temporary_user_key_delete_failed=1\n",stderr);throw;}
    }
};
Identity::Identity():impl_(std::make_shared<Impl>()){}
Identity::~Identity()=default;
const void* Identity::certificate()const{return impl_->cert;}
bool Identity::close(){return impl_.use_count()==1&&impl_->release();}

struct Client::Impl {
    std::shared_ptr<Identity::Impl> identity;
    CredHandle credential{};
    CtxtHandle context{};
    bool haveCredential=false,haveContext=false,established=false,ended=false,shutting=false;
    SECURITY_STATUS failure=SEC_E_OK;
    SecPkgContext_StreamSizes sizes{};
    Bytes input,wire,plain;
    static constexpr std::size_t bufferLimit=131072;
    static constexpr ULONG requestFlags=ISC_REQ_SEQUENCE_DETECT|ISC_REQ_REPLAY_DETECT|
        ISC_REQ_CONFIDENTIALITY|ISC_REQ_ALLOCATE_MEMORY|ISC_REQ_STREAM|ISC_REQ_USE_SUPPLIED_CREDS|
        ISC_REQ_MANUAL_CRED_VALIDATION;
    ULONG handshakeFlags=requestFlags;
    void fail(SECURITY_STATUS e){if(failure==SEC_E_OK)failure=e;}
    bool append(Bytes& to,std::span<const std::uint8_t> from) {
        if(from.size()>bufferLimit-to.size()){fail(SEC_E_INSUFFICIENT_MEMORY);return false;}
        to.insert(to.end(),from.begin(),from.end());return true;
    }
    bool release()noexcept {
        if(haveContext)DeleteSecurityContext(&context);
        if(haveCredential)FreeCredentialsHandle(&credential);
        haveContext=haveCredential=false;
        const bool ok=!identity||identity.use_count()!=1||identity->release();
        identity.reset();
        return ok;
    }
    explicit Impl(std::shared_ptr<Identity::Impl> supplied):identity(std::move(supplied)) {
        SecInvalidateHandle(&context);
        try {
            if(identity&&!identity->cert)throw std::runtime_error("TLS client identity unavailable");
            auto* cert=identity?identity->cert:nullptr;
            if(!cert)handshakeFlags &= ~ISC_REQ_USE_SUPPLIED_CREDS;
            TLS_PARAMETERS parameters{};
            parameters.grbitDisabledProtocols=SP_PROT_SSL2_CLIENT|SP_PROT_SSL3_CLIENT|SP_PROT_TLS1_0_CLIENT|
                SP_PROT_TLS1_1_CLIENT|SP_PROT_TLS1_3_CLIENT; // Initial interoperable stream supports TLS 1.2.
            SCH_CREDENTIALS cred{};cred.dwVersion=SCH_CREDENTIALS_VERSION;
            if(cert){cred.cCreds=1;cred.paCred=&cert;}
            cred.dwFlags=SCH_CRED_NO_DEFAULT_CREDS|SCH_CRED_MANUAL_CRED_VALIDATION;
            cred.cTlsParameters=1;cred.pTlsParameters=&parameters;
            TimeStamp expires{};
            const auto e=AcquireCredentialsHandleW(nullptr,const_cast<wchar_t*>(UNISP_NAME_W),SECPKG_CRED_OUTBOUND,
                nullptr,&cred,nullptr,nullptr,&credential,&expires);
            if(e!=SEC_E_OK){fail(e);return;}haveCredential=true;
            handshake(true);
        }catch(...){release();throw;}
    }
    ~Impl(){if(!release())std::fputs("tls_temporary_user_key_delete_failed=1\n",stderr);}
    bool keep_extra(SecBuffer* buffers,std::size_t count) {
        std::size_t extra=0;
        for(std::size_t i=0;i<count;++i)if(buffers[i].BufferType==SECBUFFER_EXTRA)extra=buffers[i].cbBuffer;
        if(extra>input.size()){fail(SEC_E_INVALID_TOKEN);return false;}
        Bytes tail(input.end()-static_cast<std::ptrdiff_t>(extra),input.end());input.swap(tail);return true;
    }
    bool handshake(bool first=false) {
        SecBuffer in[2]{{static_cast<ULONG>(input.size()),SECBUFFER_TOKEN,input.data()},{0,SECBUFFER_EMPTY,nullptr}};
        SecBufferDesc inDesc{SECBUFFER_VERSION,2,in};
        SecBuffer out{0,SECBUFFER_TOKEN,nullptr};SecBufferDesc outDesc{SECBUFFER_VERSION,1,&out};
        ULONG attributes=0;TimeStamp expires{};
        const auto e=InitializeSecurityContextW(&credential,haveContext?&context:nullptr,nullptr,handshakeFlags,0,0,
            first?nullptr:&inDesc,0,&context,&outDesc,&attributes,&expires);
        haveContext=SecIsValidHandle(&context)!=FALSE;
        struct Token {void* p;~Token(){if(p)FreeContextBuffer(p);}} token{out.pvBuffer};
        if(e==SEC_I_INCOMPLETE_CREDENTIALS&&!identity&&!(handshakeFlags&ISC_REQ_USE_SUPPLIED_CREDS)) {
            // Continue with the supplied empty credential. Keep the unread handshake bytes.
            handshakeFlags |= ISC_REQ_USE_SUPPLIED_CREDS;
            return handshake();
        }
        if(out.cbBuffer&&!append(wire,{static_cast<const std::uint8_t*>(out.pvBuffer),out.cbBuffer}))return false;
        if(e==SEC_E_INCOMPLETE_MESSAGE)return true; // Preserve the entire partial record.
        if(e!=SEC_E_OK&&e!=SEC_I_CONTINUE_NEEDED){fail(e);return false;}
        if(!first&&!keep_extra(in,2))return false;
        if(e==SEC_E_OK) {
            if(!(attributes&ISC_RET_CONFIDENTIALITY)){fail(SEC_E_UNSUPPORTED_FUNCTION);return false;}
            const auto sizesStatus=QueryContextAttributesW(&context,SECPKG_ATTR_STREAM_SIZES,&sizes);
            PCCERT_CONTEXT peer=nullptr;
            const auto certStatus=QueryContextAttributesW(&context,SECPKG_ATTR_REMOTE_CERT_CONTEXT,&peer);
            if(peer)CertFreeCertificateContext(peer);
            if(sizesStatus!=SEC_E_OK||certStatus!=SEC_E_OK||!peer){fail(SEC_E_NO_CREDENTIALS);return false;}
            established=true;
        }
        return true;
    }
    bool advance() {
        for(unsigned steps=0;steps<256&&!input.empty()&&failure==SEC_E_OK&&!ended;++steps) {
            const auto before=input.size();
            if(!established) {if(!handshake())return false;}
            else {
                SecBuffer buffers[4]{{static_cast<ULONG>(input.size()),SECBUFFER_DATA,input.data()},
                    {0,SECBUFFER_EMPTY,nullptr},{0,SECBUFFER_EMPTY,nullptr},{0,SECBUFFER_EMPTY,nullptr}};
                SecBufferDesc desc{SECBUFFER_VERSION,4,buffers};
                const auto e=DecryptMessage(&context,&desc,0,nullptr);
                if(e==SEC_E_INCOMPLETE_MESSAGE)break;
                if(e!=SEC_E_OK&&e!=SEC_I_CONTEXT_EXPIRED){fail(e);return false;}
                for(const auto& b:buffers)if(b.BufferType==SECBUFFER_DATA&&b.cbBuffer)
                    if(!append(plain,{static_cast<const std::uint8_t*>(b.pvBuffer),b.cbBuffer}))return false;
                if(!keep_extra(buffers,4))return false;
                if(e==SEC_I_CONTEXT_EXPIRED)ended=true;
            }
            if(input.size()==before)break;
        }
        return failure==SEC_E_OK;
    }
};
Client::Client(bool offerCertificate)
    :impl_(std::make_unique<Impl>(offerCertificate?std::make_shared<Identity::Impl>():nullptr)){}
Client::Client(Identity& identity,bool offerCertificate)
    :impl_(std::make_unique<Impl>(offerCertificate?identity.impl_:nullptr)){}
Client::~Client()=default;
bool Client::healthy()const{return impl_->failure==SEC_E_OK;}
bool Client::ready()const{return impl_->established&&healthy();}
bool Client::closed()const{return impl_->ended;}
std::uint32_t Client::error()const{return static_cast<std::uint32_t>(impl_->failure);}
std::size_t Client::max_message_size()const{return impl_->sizes.cbMaximumMessage;}
bool Client::feed(std::span<const std::uint8_t> b) {
    if(!healthy()||impl_->ended)return false;
    return impl_->append(impl_->input,b)&&impl_->advance();
}
bool Client::write(std::span<const std::uint8_t> b) {
    if(!ready()||impl_->ended||impl_->shutting||b.size()>impl_->sizes.cbMaximumMessage)return false;
    Bytes record(impl_->sizes.cbHeader+b.size()+impl_->sizes.cbTrailer);
    std::copy(b.begin(),b.end(),record.begin()+impl_->sizes.cbHeader);
    SecBuffer buffers[4]{{impl_->sizes.cbHeader,SECBUFFER_STREAM_HEADER,record.data()},
        {static_cast<ULONG>(b.size()),SECBUFFER_DATA,record.data()+impl_->sizes.cbHeader},
        {impl_->sizes.cbTrailer,SECBUFFER_STREAM_TRAILER,record.data()+impl_->sizes.cbHeader+b.size()},
        {0,SECBUFFER_EMPTY,nullptr}};
    SecBufferDesc desc{SECBUFFER_VERSION,4,buffers};
    const auto e=EncryptMessage(&impl_->context,0,&desc,0);
    if(e!=SEC_E_OK){impl_->fail(e);return false;}
    for(unsigned i=0;i<3;++i)if(!impl_->append(impl_->wire,
        {static_cast<const std::uint8_t*>(buffers[i].pvBuffer),buffers[i].cbBuffer}))return false;
    return true;
}
Bytes Client::outbound(){Bytes b;b.swap(impl_->wire);return b;}
Bytes Client::read(){Bytes b;b.swap(impl_->plain);return b;}
bool Client::shutdown() {
    if(!ready()||impl_->shutting)return false;
    impl_->shutting=true;
    impl_->input.clear();
    const auto e=generate_close_notify(impl_->context,[&](SecBufferDesc& output){
        ULONG attributes=0;TimeStamp expires{};
        return InitializeSecurityContextW(&impl_->credential,&impl_->context,nullptr,impl_->handshakeFlags,0,0,
            nullptr,0,&impl_->context,&output,&attributes,&expires);
    },[&](auto token){return impl_->append(impl_->wire,token);});
    if(e!=SEC_E_OK){impl_->fail(e);return false;}
    return true;
}
bool Client::reset_connection() {
    if(!healthy()||!impl_->haveCredential||(!impl_->shutting&&!impl_->ended)||
       !impl_->wire.empty()||!impl_->plain.empty())return false;
    if(impl_->haveContext) {
        const auto e=DeleteSecurityContext(&impl_->context);
        if(e!=SEC_E_OK){impl_->fail(e);return false;}
        impl_->haveContext=false;
    }
    SecInvalidateHandle(&impl_->context);
    impl_->established=impl_->ended=impl_->shutting=false;
    impl_->handshakeFlags=impl_->identity?Impl::requestFlags:Impl::requestFlags&~ISC_REQ_USE_SUPPLIED_CREDS;
    impl_->sizes={};impl_->input.clear();
    return impl_->handshake(true);
}
bool Client::close(){return impl_->release();}

struct Server::Impl {
    std::shared_ptr<Identity::Impl> identity;
    CredHandle credential{};
    CtxtHandle context{};
    bool haveCredential=false,haveContext=false,established=false,ended=false,shutting=false;
    SECURITY_STATUS failure=SEC_E_OK;
    SecPkgContext_StreamSizes sizes{};
    Bytes input,wire,plain;
    static constexpr std::size_t bufferLimit=Server::MaxBufferedBytes;
    static constexpr ULONG requestFlags=ASC_REQ_SEQUENCE_DETECT|ASC_REQ_REPLAY_DETECT|
        ASC_REQ_CONFIDENTIALITY|ASC_REQ_ALLOCATE_MEMORY|ASC_REQ_STREAM;

    void fail(SECURITY_STATUS e){if(failure==SEC_E_OK)failure=e;}
    bool append(Bytes& to,std::span<const std::uint8_t> from) {
        if(from.size()>bufferLimit-to.size()){fail(SEC_E_INSUFFICIENT_MEMORY);return false;}
        to.insert(to.end(),from.begin(),from.end());return true;
    }
    bool release()noexcept {
        bool ok=true;
        if(haveContext){if(DeleteSecurityContext(&context)!=SEC_E_OK)ok=false;haveContext=false;}
        if(haveCredential){if(FreeCredentialsHandle(&credential)!=SEC_E_OK)ok=false;haveCredential=false;}
        if(identity&&identity.use_count()==1&&!identity->release())ok=false;
        identity.reset();return ok;
    }
    bool keep_extra(SecBuffer* buffers,std::size_t count) {
        std::size_t extra=0;
        for(std::size_t i=0;i<count;++i)if(buffers[i].BufferType==SECBUFFER_EXTRA)extra=buffers[i].cbBuffer;
        if(extra>input.size()){fail(SEC_E_INVALID_TOKEN);return false;}
        Bytes tail(input.end()-static_cast<std::ptrdiff_t>(extra),input.end());input.swap(tail);return true;
    }
    bool handshake() {
        SecBuffer in[2]{{static_cast<ULONG>(input.size()),SECBUFFER_TOKEN,input.data()},
            {0,SECBUFFER_EMPTY,nullptr}};
        SecBufferDesc inDesc{SECBUFFER_VERSION,2,in};
        SecBuffer out{0,SECBUFFER_TOKEN,nullptr};SecBufferDesc outDesc{SECBUFFER_VERSION,1,&out};
        ULONG attributes=0;TimeStamp expires{};
        const auto e=AcceptSecurityContext(&credential,haveContext?&context:nullptr,&inDesc,
            requestFlags,SECURITY_NATIVE_DREP,&context,&outDesc,&attributes,&expires);
        haveContext=SecIsValidHandle(&context)!=FALSE;
        struct Token {void* p;~Token(){if(p)FreeContextBuffer(p);}} token{out.pvBuffer};
        if(out.cbBuffer&&!append(wire,{static_cast<const std::uint8_t*>(out.pvBuffer),out.cbBuffer}))return false;
        if(e==SEC_E_INCOMPLETE_MESSAGE)return true;
        if(e!=SEC_E_OK&&e!=SEC_I_CONTINUE_NEEDED&&e!=SEC_I_CONTEXT_EXPIRED){fail(e);return false;}
        if(!keep_extra(in,2))return false;
        if(e==SEC_E_OK) {
            if(!(attributes&ASC_RET_CONFIDENTIALITY)){fail(SEC_E_UNSUPPORTED_FUNCTION);return false;}
            const auto sizesStatus=QueryContextAttributesW(&context,SECPKG_ATTR_STREAM_SIZES,&sizes);
            if(sizesStatus!=SEC_E_OK){fail(sizesStatus);return false;}
            established=true;
        } else if(e==SEC_I_CONTEXT_EXPIRED)ended=true;
        return true;
    }
    bool advance() {
        for(unsigned steps=0;steps<256&&!input.empty()&&failure==SEC_E_OK&&!ended;++steps) {
            const auto before=input.size();
            if(!established) {if(!handshake())return false;}
            else {
                const auto recordType = static_cast<unsigned>(input.front());
                SecBuffer buffers[4]{{static_cast<ULONG>(input.size()),SECBUFFER_DATA,input.data()},
                    {0,SECBUFFER_EMPTY,nullptr},{0,SECBUFFER_EMPTY,nullptr},{0,SECBUFFER_EMPTY,nullptr}};
                SecBufferDesc desc{SECBUFFER_VERSION,4,buffers};
                const auto e=DecryptMessage(&context,&desc,0,nullptr);
                if(e==SEC_E_INCOMPLETE_MESSAGE)break;
                if(e!=SEC_E_OK&&e!=SEC_I_CONTEXT_EXPIRED){
                    std::cerr << "tls_receive_decryption_failed status=" << static_cast<std::uint32_t>(e)
                              << " record_type=" << recordType << " buffered_bytes=" << before << '\n';
                    fail(e);
                    return false;
                }
                for(const auto& b:buffers)if(b.BufferType==SECBUFFER_DATA&&b.cbBuffer)
                    if(!append(plain,{static_cast<const std::uint8_t*>(b.pvBuffer),b.cbBuffer}))return false;
                if(!keep_extra(buffers,4))return false;
                if(e==SEC_I_CONTEXT_EXPIRED)ended=true;
            }
            if(input.size()==before)break;
        }
        return failure==SEC_E_OK;
    }
    explicit Impl(std::shared_ptr<Identity::Impl> supplied):identity(std::move(supplied)) {
        SecInvalidateHandle(&context);
        try {
            if(!identity||!identity->cert)throw std::runtime_error("TLS server identity unavailable");
            auto* cert=identity->cert;
            TLS_PARAMETERS parameters{};
            parameters.grbitDisabledProtocols=SP_PROT_SSL2_SERVER|SP_PROT_SSL3_SERVER|SP_PROT_TLS1_0_SERVER|
                SP_PROT_TLS1_1_SERVER|SP_PROT_TLS1_3_SERVER;
            SCH_CREDENTIALS cred{};cred.dwVersion=SCH_CREDENTIALS_VERSION;cred.cCreds=1;cred.paCred=&cert;
            cred.dwFlags=SCH_CRED_NO_SYSTEM_MAPPER;cred.cTlsParameters=1;cred.pTlsParameters=&parameters;
            TimeStamp expires{};
            const auto e=AcquireCredentialsHandleW(nullptr,const_cast<wchar_t*>(UNISP_NAME_W),SECPKG_CRED_INBOUND,
                nullptr,&cred,nullptr,nullptr,&credential,&expires);
            if(e!=SEC_E_OK){fail(e);return;}haveCredential=true;
        }catch(...){release();throw;}
    }
    ~Impl(){if(!release())std::fputs("tls_server_release_failed=1\n",stderr);}
};
Server::Server():impl_(std::make_unique<Impl>(std::make_shared<Identity>()->impl_)){}
Server::Server(Identity& identity):impl_(std::make_unique<Impl>(identity.impl_)){}
Server::~Server()=default;
bool Server::healthy()const{return impl_->failure==SEC_E_OK;}
bool Server::ready()const{return impl_->established&&healthy();}
bool Server::closed()const{return impl_->ended;}
std::uint32_t Server::error()const{return static_cast<std::uint32_t>(impl_->failure);}
std::size_t Server::max_message_size()const{return impl_->sizes.cbMaximumMessage;}
bool Server::feed(std::span<const std::uint8_t> b) {
    if(!healthy()||impl_->ended)return false;
    return impl_->append(impl_->input,b)&&impl_->advance();
}
bool Server::write(std::span<const std::uint8_t> b) {
    if(!ready()||impl_->ended||impl_->shutting||b.size()>impl_->sizes.cbMaximumMessage)return false;
    Bytes record(impl_->sizes.cbHeader+b.size()+impl_->sizes.cbTrailer);
    std::copy(b.begin(),b.end(),record.begin()+impl_->sizes.cbHeader);
    SecBuffer buffers[4]{{impl_->sizes.cbHeader,SECBUFFER_STREAM_HEADER,record.data()},
        {static_cast<ULONG>(b.size()),SECBUFFER_DATA,record.data()+impl_->sizes.cbHeader},
        {impl_->sizes.cbTrailer,SECBUFFER_STREAM_TRAILER,record.data()+impl_->sizes.cbHeader+b.size()},
        {0,SECBUFFER_EMPTY,nullptr}};
    SecBufferDesc desc{SECBUFFER_VERSION,4,buffers};
    const auto e=EncryptMessage(&impl_->context,0,&desc,0);
    if(e!=SEC_E_OK){impl_->fail(e);return false;}
    for(unsigned i=0;i<3;++i)if(!impl_->append(impl_->wire,
        {static_cast<const std::uint8_t*>(buffers[i].pvBuffer),buffers[i].cbBuffer}))return false;
    return true;
}
Bytes Server::outbound(){Bytes b;b.swap(impl_->wire);return b;}
Bytes Server::read(){Bytes b;b.swap(impl_->plain);return b;}
bool Server::shutdown() {
    if(!ready()||impl_->shutting)return false;
    impl_->shutting=true;
    impl_->input.clear();
    const auto e=generate_close_notify(impl_->context,[&](SecBufferDesc& output){
        ULONG attributes=0;TimeStamp expires{};
        return AcceptSecurityContext(&impl_->credential,&impl_->context,nullptr,Impl::requestFlags,
            SECURITY_NATIVE_DREP,&impl_->context,&output,&attributes,&expires);
    },[&](auto token){return impl_->append(impl_->wire,token);});
    if(e!=SEC_E_OK){impl_->fail(e);return false;}
    impl_->ended=true;
    return true;
}
bool Server::close(){return impl_->release();}
} // namespace tx10ub::tls
