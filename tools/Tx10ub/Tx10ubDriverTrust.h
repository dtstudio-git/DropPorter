#pragma once
#include <windows.h>
#include <softpub.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <mscat.h>
#include <array>
#include <filesystem>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <system_error>
#include <vector>
namespace tx10ub::security {
namespace fs = std::filesystem;
inline constexpr wchar_t kSigningThumbprint[]=L"D2F1EC33AAB1FD8E2D2D0E6C7E933E6C3D073380";
[[noreturn]] inline void Fail(const std::string& message) { throw std::runtime_error(message); }
[[noreturn]] inline void FailWin32(const char* message, DWORD error=GetLastError()) {
    throw std::system_error(static_cast<int>(error), std::system_category(),message);
}
inline std::wstring ThumbprintForFile(const fs::path& path) {
    HCERTSTORE store = nullptr;
    HCRYPTMSG message = nullptr;
    DWORD encoding = 0, content = 0, format = 0;
    if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, path.c_str(),
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED|CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED, CERT_QUERY_FORMAT_FLAG_BINARY,
        0, &encoding, &content, &format, &store, &message, nullptr)) FailWin32("driver_signature_certificate_read_failed");
    struct CryptoCleanup {
        HCERTSTORE store; HCRYPTMSG message;
        ~CryptoCleanup() { if (message) CryptMsgClose(message); if (store) CertCloseStore(store, 0); }
    } cleanup{store, message};
    DWORD signerBytes = 0;
    if (!CryptMsgGetParam(message, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &signerBytes) ||
        signerBytes < sizeof(CMSG_SIGNER_INFO)) FailWin32("driver_signer_info_size_failed");
    std::vector<BYTE> signerStorage(signerBytes);
    if (!CryptMsgGetParam(message, CMSG_SIGNER_INFO_PARAM, 0, signerStorage.data(), &signerBytes)) FailWin32("driver_signer_info_read_failed");
    const auto* signer = reinterpret_cast<const CMSG_SIGNER_INFO*>(signerStorage.data());
    CERT_INFO findInfo{};
    findInfo.Issuer = signer->Issuer;
    findInfo.SerialNumber = signer->SerialNumber;
    PCCERT_CONTEXT certificate = CertFindCertificateInStore(store, encoding,
        0, CERT_FIND_SUBJECT_CERT, &findInfo, nullptr);
    if (!certificate) FailWin32("driver_signing_certificate_not_found");
    struct CertCleanup { PCCERT_CONTEXT value; ~CertCleanup() { CertFreeCertificateContext(value); } } certCleanup{certificate};
    std::array<BYTE, 20> thumbprint{};
    DWORD thumbprintBytes = static_cast<DWORD>(thumbprint.size());
    if (!CertGetCertificateContextProperty(certificate, CERT_SHA1_HASH_PROP_ID,
        thumbprint.data(), &thumbprintBytes) || thumbprintBytes != thumbprint.size()) FailWin32("driver_signer_thumbprint_unavailable");
    std::wostringstream out;
    out << std::hex << std::uppercase << std::setfill(L'0');
    for (BYTE byte : thumbprint) out << std::setw(2) << static_cast<unsigned>(byte);
    return out.str();
}

inline void VerifySignedFile(const fs::path& path, const wchar_t* expectedThumbprint) {
    if (!fs::is_regular_file(path)) Fail("runtime_driver_image_missing");
    WINTRUST_FILE_INFO file{};
    file.cbStruct = sizeof(file);
    file.pcwszFilePath = path.c_str();
    WINTRUST_DATA trust{};
    trust.cbStruct = sizeof(trust);
    trust.dwUIChoice = WTD_UI_NONE;
    trust.fdwRevocationChecks = WTD_REVOKE_NONE;
    trust.dwUnionChoice = WTD_CHOICE_FILE;
    trust.pFile = &file;
    trust.dwStateAction = WTD_STATEACTION_IGNORE;
    trust.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE;
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    const LONG result = WinVerifyTrust(nullptr, &action, &trust);
    if (result != ERROR_SUCCESS) Fail("runtime_driver_signature_not_trusted_" + std::to_string(static_cast<unsigned long>(result)));
    if (_wcsicmp(ThumbprintForFile(path).c_str(), expectedThumbprint) != 0) Fail("runtime_driver_signer_mismatch");
}

inline void VerifySignedDriver(const fs::path& path) {
    VerifySignedFile(path, kSigningThumbprint);
}

inline void VerifyCatalogMember(const fs::path& catalog,const fs::path& member) {
    HCATADMIN admin{};
    if(!CryptCATAdminAcquireContext2(&admin,nullptr,L"SHA256",nullptr,0))FailWin32("catalog_hash_context_failed");
    struct AdminCleanup { HCATADMIN value;~AdminCleanup(){CryptCATAdminReleaseContext(value,0);} } adminCleanup{admin};
    HANDLE file=CreateFileW(member.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,0,nullptr);
    if(file==INVALID_HANDLE_VALUE)FailWin32("catalog_member_open_failed");
    struct FileCleanup { HANDLE value;~FileCleanup(){CloseHandle(value);} } fileCleanup{file};
    DWORD size{};
    if(!CryptCATAdminCalcHashFromFileHandle2(admin,file,&size,nullptr,0)||size!=32)
        Fail("catalog_member_hash_size_failed");
    std::vector<BYTE> hash(size);
    if(!CryptCATAdminCalcHashFromFileHandle2(admin,file,&size,hash.data(),0)||size!=hash.size())
        FailWin32("catalog_member_hash_failed");
    std::wostringstream tag;
    tag<<std::hex<<std::uppercase<<std::setfill(L'0');
    for(BYTE byte:hash)tag<<std::setw(2)<<static_cast<unsigned>(byte);
    const auto memberTag=tag.str();
    WINTRUST_CATALOG_INFO info{};
    info.cbStruct=sizeof(info);info.pcwszCatalogFilePath=catalog.c_str();
    info.pcwszMemberTag=memberTag.c_str();info.pcwszMemberFilePath=member.c_str();
    info.hMemberFile=file;info.pbCalculatedFileHash=hash.data();info.cbCalculatedFileHash=size;info.hCatAdmin=admin;
    WINTRUST_DATA trust{};
    trust.cbStruct=sizeof(trust);trust.dwUIChoice=WTD_UI_NONE;
    trust.fdwRevocationChecks=WTD_REVOKE_NONE;trust.dwUnionChoice=WTD_CHOICE_CATALOG;
    trust.pCatalog=&info;trust.dwStateAction=WTD_STATEACTION_IGNORE;
    trust.dwProvFlags=WTD_CACHE_ONLY_URL_RETRIEVAL|WTD_REVOCATION_CHECK_NONE;
    GUID action=WINTRUST_ACTION_GENERIC_VERIFY_V2;
    if(WinVerifyTrust(nullptr,&action,&trust)!=ERROR_SUCCESS)Fail("catalog_member_verification_failed");
}

} // namespace tx10ub::security
