#pragma once
#include <roapi.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.Devices.Bluetooth.Advertisement.h>
#include <winrt/Windows.Storage.Streams.h>
#include <atomic>
#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <iostream>

#pragma comment(lib, "windowsapp.lib")

namespace tx10ub {
inline std::atomic<bool> ble_cancel_requested{false};
inline BOOL WINAPI ble_console_cancel(DWORD event) {
    if(event!=CTRL_C_EVENT&&event!=CTRL_BREAK_EVENT)return FALSE;
    ble_cancel_requested=true;return TRUE;
}
// AirDrop manufacturer TLV, following owly's proto/ble.rs (version 3).
// Zero contact hashes target Everyone receivers; this is not authentication.
enum class BleProfile { everyone_v3, everyone_v2_comparison };
inline std::array<uint8_t,20> everyone_ble_payload(const GUID& random,
    BleProfile profile=BleProfile::everyone_v3) {
    // Layout corroborated by hexway/apple_bleee parse_airdrop_r and owly
    // proto/ble.rs. V2's eight zero prefix bytes and version come from the
    // user's normal iPhone trace; replace only its contact hashes with zeros.
    // Everyone wake-up with this V2 comparison remains hardware-unverified.
    if(profile==BleProfile::everyone_v2_comparison)
        return {5,18,0,0,0,0,0,0,0,0,2,0,0,0,0,0,0,0,0,0};
    return {5,18,0x40,random.Data4[0],random.Data4[1],random.Data4[2],
            0,0,0,0,3,0,0,0,0,0,0,0,0,0};
}

class BleAdvertisement {
    using Publisher=winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementPublisher;
    using Status=winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementPublisherStatus;
    struct State {
        std::atomic<bool> failed{false};
        std::atomic<bool> stopping{false};
        std::atomic<std::int64_t> startedAtUs{0};
        std::atomic<Status> status{Status::Created};
        std::atomic<int> error{0};
    };
    std::shared_ptr<State> state_=std::make_shared<State>();
    Publisher publisher_{nullptr};
    winrt::event_token token_{};
    std::int64_t startDeadlineUs_{};
    bool subscribed_=false,initialized_=false,closed_=false,close_ok_=true,handler_=false;
    static std::int64_t now_us() noexcept {
        return std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
    }
public:
    BleAdvertisement()=default;
    BleAdvertisement(const BleAdvertisement&)=delete;
    BleAdvertisement& operator=(const BleAdvertisement&)=delete;
    ~BleAdvertisement() {close();}
    bool begin(BleProfile profile, bool consoleCancellation) noexcept {
        try {
            ble_cancel_requested=false;
            if(consoleCancellation) {
                winrt::check_bool(SetConsoleCtrlHandler(ble_console_cancel,TRUE));
                handler_=true;
            }
            winrt::check_hresult(RoInitialize(RO_INIT_MULTITHREADED));
            initialized_=true;
            GUID random{};
            if(profile==BleProfile::everyone_v3)winrt::check_hresult(CoCreateGuid(&random));
            const auto payload=everyone_ble_payload(random,profile);
            using namespace winrt::Windows::Devices::Bluetooth::Advertisement;
            winrt::Windows::Storage::Streams::DataWriter writer;
            writer.WriteBytes(payload);
            BluetoothLEAdvertisement advertisement;
            advertisement.ManufacturerData().Append(BluetoothLEManufacturerData(0x004c,writer.DetachBuffer()));
            publisher_=Publisher(advertisement);
            // Windows controls interval and PDU policy; do not claim BlueZ's
            // 100-ms connectable setting or add system-reserved Flags fields.
            token_=publisher_.StatusChanged([state=state_](const auto&,const auto& args) {
                const auto status=args.Status();
                state->error.store(static_cast<int>(args.Error()));
                if(status==Status::Aborted||
                   ((status==Status::Stopped||status==Status::Stopping)&&!state->stopping.load())||
                   (status==Status::Waiting&&state->startedAtUs.load()!=0))state->failed=true;
                if(status==Status::Started) {
                    std::int64_t unset=0;
                    state->startedAtUs.compare_exchange_strong(unset,now_us());
                }
                state->status=status;
            });
            subscribed_=true;
            startDeadlineUs_=now_us()+5'000'000;
            publisher_.Start();
            return true;
        } catch(const winrt::hresult_error& e) {
            std::wcerr<<L"ble_start_hresult="<<e.code().value<<L'\n';
        } catch(...) {std::wcerr<<L"ble_start_failed=1\n";}
        state_->failed=true;
        return false;
    }
    std::int64_t started_at_us() const noexcept { return state_->startedAtUs.load(); }
    bool failed() const noexcept {
        const auto startedAt=started_at_us();
        return state_->failed.load() || ble_cancel_requested.load() ||
            (startDeadlineUs_ && (startedAt?startedAt:now_us())>=startDeadlineUs_);
    }
    bool wait_until_started() noexcept {
        while(!failed()) {
            if(state_->status.load()==Status::Started)return true;
            Sleep(10);
        }
        std::wcerr<<L"ble_start_failed status="<<static_cast<int>(state_->status.load())
                  <<L" error="<<state_->error.load()<<L'\n';
        state_->failed=true;
        return false;
    }
    bool start(BleProfile profile=BleProfile::everyone_v3) noexcept {
        if(!begin(profile,true)||!wait_until_started())return false;
        std::wcout<<L"ble_advertising_started=1; profile="
            <<(profile==BleProfile::everyone_v2_comparison?L"airdrop_v2_everyone_comparison":L"airdrop_v3_everyone")
            <<L"; radio_policy=windows\n";
        return true;
    }
    bool radio_unavailable() const noexcept {
        using Error = winrt::Windows::Devices::Bluetooth::BluetoothError;
        const auto error = static_cast<Error>(state_->error.load());
        return error == Error::RadioNotAvailable || error == Error::DisabledByUser;
    }
    bool healthy() const noexcept {
        if(!publisher_||ble_cancel_requested.load()||state_->failed.load()||state_->status.load()!=Status::Started) {
            std::wcerr<<L"ble_advertising_unavailable status="<<static_cast<int>(state_->status.load())
                      <<L" error="<<state_->error.load()<<L'\n';
            return false;
        }
        return true;
    }
    bool close() noexcept {
        if(closed_)return close_ok_;
        closed_=true;
        if(publisher_) {
            state_->stopping=true;
            try {
                publisher_.Stop();
                const auto deadline=GetTickCount64()+5000;
                for(;;) {
                    const auto status=publisher_.Status();
                    if(status==Status::Stopped||status==Status::Aborted||status==Status::Created)break;
                    if(GetTickCount64()>=deadline){close_ok_=false;break;}
                    Sleep(10);
                }
            } catch(...) {close_ok_=false;}
            if(subscribed_) {
                try { publisher_.StatusChanged(token_); } catch(...) { close_ok_=false; }
                subscribed_=false;
            }
            publisher_=nullptr;
            std::wcout<<L"ble_stop_confirmed="<<close_ok_<<L'\n';
        }
        if(initialized_){RoUninitialize();initialized_=false;}
        if(handler_){SetConsoleCtrlHandler(ble_console_cancel,FALSE);handler_=false;}
        return close_ok_;
    }
};
}
