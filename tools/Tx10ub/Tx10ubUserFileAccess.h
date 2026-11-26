#pragma once
#include <windows.h>
#include <exception>
#include <stdexcept>
#include <system_error>

namespace tx10ub {
// Keep file capabilities tied to the desktop user when UAC uses another
// account. Driver and radio operations must run outside this scope.
class ScopedUserFileAccess {
public:
    explicit ScopedUserFileAccess(DWORD ownerPid) {
        if(!ownerPid)return;
        HANDLE process=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,FALSE,ownerPid);
        if(!process)fail("file_owner_process_unavailable");
        struct Close { HANDLE value;~Close(){if(value)CloseHandle(value);} } processGuard{process};
        if(WaitForSingleObject(process,0)!=WAIT_TIMEOUT)
            throw std::runtime_error("file_owner_has_exited");
        HANDLE token{};
        if(!OpenProcessToken(process,TOKEN_QUERY|TOKEN_IMPERSONATE|TOKEN_DUPLICATE,&token))
            fail("file_owner_token_unavailable");
        Close tokenGuard{token};
        if(!ImpersonateLoggedOnUser(token))fail("file_owner_impersonation_failed");
        impersonating_=true;
    }
    ~ScopedUserFileAccess(){
        if(impersonating_&&!RevertToSelf()){
            // Continuing privileged work under an unintended token is unsafe.
            TerminateProcess(GetCurrentProcess(),ERROR_ACCESS_DENIED);
            std::terminate();
        }
    }
    ScopedUserFileAccess(const ScopedUserFileAccess&)=delete;
    ScopedUserFileAccess& operator=(const ScopedUserFileAccess&)=delete;
private:
    [[noreturn]] static void fail(const char* action){
        throw std::system_error(static_cast<int>(GetLastError()),std::system_category(),action);
    }
    bool impersonating_{};
};
} // namespace tx10ub
