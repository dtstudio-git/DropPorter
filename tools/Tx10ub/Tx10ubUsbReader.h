#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winioctl.h>

#include <cstdint>
#include <new>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace tx10ub::usb {
// Owns the exclusive USBPcap session and its single overlapped read buffer.
// A span returned by poll() or stop() refers to that buffer and must be
// consumed before calling poll() again.
class Reader {
public:
    using Bytes = std::span<const std::uint8_t>;

    Reader(std::wstring hub, unsigned address)
        : hub_(std::move(hub)), address_(address) {}

    Reader(const Reader&) = delete;
    Reader& operator=(const Reader&) = delete;

    ~Reader() { stop(); }

    bool begin() {
        if (stopped_) {
            fail("state_error", ERROR_INVALID_STATE);
            return false;
        }
        if (attempted_) return capture_started_ && healthy();
        attempted_ = true;

        if (address_ < 1 || address_ > 127) {
            fail("address_error", ERROR_INVALID_PARAMETER);
            return false;
        }
        if (hub_.rfind(L"\\\\.\\USBPcap", 0) != 0) {
            fail("hub_error", ERROR_INVALID_NAME);
            return false;
        }

        device_.value = CreateFileW(hub_.c_str(), GENERIC_READ | GENERIC_WRITE,
                                    0, nullptr, OPEN_EXISTING,
                                    FILE_FLAG_OVERLAPPED, nullptr);
        if (device_.value == INVALID_HANDLE_VALUE) {
            fail("open_error", GetLastError());
            return false;
        }

        read_event_.value = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!read_event_.value) {
            fail("event_error", GetLastError());
            return false;
        }

        try {
            buffer_.resize(1024 * 1024);
        } catch (const std::bad_alloc&) {
            fail("buffer_error", ERROR_NOT_ENOUGH_MEMORY);
            return false;
        }

        DWORD snaplen = 1024 * 1024;
        DWORD capacity = 8 * 1024 * 1024;
        // USBPCAP_ADDRESS_FILTER is four DWORD bitsets and one BOOLEAN.
        unsigned char filter[17]{};
        filter[address_ / 8] = static_cast<unsigned char>(1u << (address_ % 8));

        DWORD error{};
        if (!control(device_.value, ioctlSnap, &snaplen, sizeof(snaplen), error)) {
            fail("snap_error", error);
            return false;
        }
        if (!control(device_.value, ioctlSize, &capacity, sizeof(capacity), error)) {
            fail("size_error", error);
            return false;
        }
        if (!control(device_.value, ioctlStart, filter, sizeof(filter), error)) {
            fail("start_error", error);
            return false;
        }

        capture_started_ = true;
        return true;
    }

    // Starts at most one read and waits no longer than max_wait_ms. An empty
    // span means the read is still pending, completed with zero bytes, or the
    // reader is stopped/failed. No subsequent read starts until the next call.
    // An optional owner completion event interrupts the wait without consuming
    // or cancelling the outstanding USB read. The next poll harvests that read.
    Bytes poll(DWORD max_wait_ms, HANDLE owner_completion = nullptr) {
        if (!capture_started_ || stopped_ || !healthy()) return {};

        // The caller's next poll is its signal that the previous view was used.
        if (!read_pending_) {
            if (!ResetEvent(read_event_.value)) {
                fail("read_error", GetLastError());
                return {};
            }
            read_operation_ = {};
            read_operation_.hEvent = read_event_.value;
            if (ReadFile(device_.value, buffer_.data(),
                         static_cast<DWORD>(buffer_.size()), nullptr,
                         &read_operation_)) {
                DWORD received{};
                if (GetOverlappedResult(device_.value, &read_operation_,
                                        &received, FALSE))
                    return deliver(received, "read_completion_error");
                const DWORD error = GetLastError();
                if (error != ERROR_IO_INCOMPLETE) {
                    fail("read_completion_error", error);
                    return {};
                }
            } else {
                const DWORD error = GetLastError();
                if (error != ERROR_IO_PENDING) {
                    fail("read_error", error);
                    return {};
                }
            }
            read_pending_ = true;
        }

        const HANDLE events[]{read_event_.value, owner_completion};
        const DWORD wait = owner_completion ? WaitForMultipleObjects(2, events, FALSE, max_wait_ms) :
                                             WaitForSingleObject(read_event_.value, max_wait_ms);
        if (owner_completion && wait == WAIT_OBJECT_0 + 1) return {};
        if (wait == WAIT_TIMEOUT) return {};
        if (wait == WAIT_FAILED) {
            fail("read_wait_error", GetLastError());
            return {};
        }
        if (wait != WAIT_OBJECT_0) {
            fail("read_wait_error", ERROR_GEN_FAILURE);
            return {};
        }

        DWORD received{};
        if (!GetOverlappedResult(device_.value, &read_operation_, &received, FALSE)) {
            const DWORD error = GetLastError();
            if (error == ERROR_IO_INCOMPLETE) {
                // The event was signaled, so do not spin on a stale signal.
                // Leave the operation marked pending for stop() to drain.
                fail("read_completion_error", error);
                return {};
            }
            read_pending_ = false;
            fail("read_completion_error", error);
            return {};
        }
        read_pending_ = false;
        return deliver(received, "read_completion_error");
    }

    // Cancels and drains the one outstanding read, returns any read that won
    // the cancellation race, then sends USBPcap STOP. The returned tail is
    // valid until this Reader is destroyed.
    Bytes stop() noexcept {
        if (stopped_) return {};
        stopped_ = true;

        std::size_t tail_size{};
        if (read_pending_) {
            if (!CancelIoEx(device_.value, &read_operation_)) {
                const DWORD cancel_error = GetLastError();
                if (cancel_error != ERROR_NOT_FOUND)
                    fail("cancel_error", cancel_error);
            }

            DWORD received{};
            if (GetOverlappedResult(device_.value, &read_operation_, &received, TRUE)) {
                read_pending_ = false;
                if (received <= buffer_.size()) tail_size = received;
                else fail("read_completion_error", ERROR_INVALID_DATA);
            } else {
                const DWORD error = GetLastError();
                read_pending_ = false;
                if (error != ERROR_OPERATION_ABORTED)
                    fail("read_completion_error", error);
            }
        }

        if (capture_started_) {
            DWORD error{};
            stop_succeeded_ = control(device_.value, ioctlStop, nullptr, 0, error);
            capture_started_ = false;
            if (!stop_succeeded_) fail("stop_error", error);
        }

        return Bytes(buffer_).first(tail_size);
    }

    bool healthy() const { return error_name_ == nullptr; }
    bool stop_succeeded() const { return stop_succeeded_; }
    const char* error_name() const { return error_name_ ? error_name_ : ""; }
    DWORD error_code() const { return error_code_; }

private:
    struct Handle {
        HANDLE value = INVALID_HANDLE_VALUE;
        Handle() = default;
        Handle(const Handle&) = delete;
        Handle& operator=(const Handle&) = delete;
        ~Handle() {
            if (value != INVALID_HANDLE_VALUE && value != nullptr) CloseHandle(value);
        }
    };

    static constexpr DWORD ioctlSize =
        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS);
    static constexpr DWORD ioctlStart = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801,
        METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS);
    static constexpr DWORD ioctlStop = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802,
        METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS);
    static constexpr DWORD ioctlSnap =
        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_READ_ACCESS);

    std::wstring hub_;
    unsigned address_{};
    Handle device_;
    Handle read_event_;
    std::vector<std::uint8_t> buffer_;
    OVERLAPPED read_operation_{};
    const char* error_name_{};
    DWORD error_code_{};
    bool attempted_{};
    bool capture_started_{};
    bool read_pending_{};
    bool stopped_{};
    bool stop_succeeded_{};

    void fail(const char* name, DWORD code) {
        if (!error_name_) {
            error_name_ = name;
            error_code_ = code;
        }
    }

    static bool control(HANDLE device, DWORD code, void* input, DWORD size,
                        DWORD& error) {
        Handle event;
        event.value = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!event.value) {
            error = GetLastError();
            return false;
        }

        OVERLAPPED operation{};
        operation.hEvent = event.value;
        DWORD returned{};
        if (DeviceIoControl(device, code, input, size, nullptr, 0, &returned,
                            &operation)) return true;

        error = GetLastError();
        if (error != ERROR_IO_PENDING) return false;
        if (GetOverlappedResult(device, &operation, &returned, TRUE)) return true;
        error = GetLastError();
        return false;
    }

    Bytes deliver(DWORD received, const char* error_name) {
        if (received > buffer_.size()) {
            fail(error_name, ERROR_INVALID_DATA);
            return {};
        }
        return Bytes(buffer_).first(received);
    }
};
}
