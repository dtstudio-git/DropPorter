#pragma once

#include "Tx10ubUsbClock.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <utility>
#include <vector>

namespace tx10ub::usb {

// Pure same-session estimator for submitted mDNS/TCP control -> USB OUT transfer.
// The USB transport rewrites only Sequence Control in the captured MPDU, so
// matching normalizes that field while retaining every other submitted byte.
class DataTiming {
public:
    using Time = awdlwin::discovery::MonotonicTime;
    using Delay = std::chrono::microseconds;

    static constexpr std::size_t sample_limit = 8;
    static constexpr std::size_t maximum_mpdu_bytes = 1600;
    static constexpr Delay maximum_delay{100'000};
    static constexpr Delay pending_lifetime=awdlwin::tx10ub::usb_clock::transport_pending_lifetime;
    static constexpr Delay sample_freshness{10'000'000};

    bool register_query(std::span<const std::uint8_t> mpdu, Time submitted_at) {
        if (!valid_time(submitted_at) || !valid_mpdu(mpdu)) {
            invalidate_samples();
            pending_.reset();
            return false;
        }
        expire_pending(submitted_at);
        if ((latest_observation_ && submitted_at < *latest_observation_) ||
            (pending_ && submitted_at < pending_->submitted_at)) {
            invalidate_samples();
            pending_.reset();
            return false;
        }

        auto identity = normalized(mpdu);
        if (pending_ && pending_->identity == identity) return true;
        pending_ = Pending{std::move(identity), submitted_at};
        return true;
    }

    void cancel_query() noexcept { pending_.reset(); }

    // The expected MPDU has already had its Sequence Control field cleared.
    static bool matches(std::span<const std::uint8_t> expected,
                        std::span<const std::uint8_t> observed) noexcept {
        return expected.size() == observed.size() && valid_mpdu(observed) &&
            std::equal(expected.begin(), expected.begin() + 22, observed.begin()) &&
            std::equal(expected.begin() + 24, expected.end(), observed.begin() + 24);
    }

    std::optional<Delay> observe(std::span<const std::uint8_t> mpdu, Time observed_at) {
        if (!valid_time(observed_at)) {
            invalidate_samples();
            pending_.reset();
            return std::nullopt;
        }
        if (latest_observation_ && observed_at < *latest_observation_) {
            invalidate_samples();
            pending_.reset();
            return std::nullopt;
        }
        if (!valid_mpdu(mpdu)) {
            invalidate_samples();
            pending_.reset();
            return std::nullopt;
        }
        if (!pending_ || !matches(pending_->identity, mpdu)) {
            expire_pending(observed_at);
            return std::nullopt;
        }

        const auto submitted_at = pending_->submitted_at;
        pending_.reset(); // An exact USB OUT can train only once.
        if (observed_at < submitted_at) {
            invalidate_samples();
            return std::nullopt;
        }

        const auto actual_delay = std::chrono::duration_cast<Delay>(observed_at - submitted_at);
        latest_observation_ = observed_at;
        if (actual_delay > pending_lifetime) {
            invalidate_samples();
            return std::nullopt;
        }
        if (actual_delay < Delay::zero() || actual_delay > maximum_delay) {
            invalidate_samples();
            return actual_delay;
        }

        retain_fresh_samples(observed_at);
        samples_.push_back(TimedSample{actual_delay, observed_at});
        if (samples_.size() > sample_limit) samples_.erase(samples_.begin());
        return actual_delay;
    }

    std::optional<Delay> prediction(Time now) const {
        if (!valid_time(now) || pending_expired(now)) return std::nullopt;
        std::array<Delay, sample_limit> ordered{};
        std::size_t count = 0;
        for (const auto& sample : samples_)
            if (is_fresh(sample, now)) ordered[count++] = sample.delay;
        if (!count) return std::nullopt;
        std::sort(ordered.begin(), ordered.begin() + static_cast<std::ptrdiff_t>(count));
        const auto middle = count / 2;
        if (count % 2 != 0) return ordered[middle];
        return Delay{(ordered[middle - 1].count() + ordered[middle].count()) / 2};
    }

    std::optional<Delay> sample_spread(Time now) const {
        const auto fresh = fresh_samples(now);
        if (fresh.empty()) return std::nullopt;
        auto minimum = fresh.front().delay;
        auto maximum = fresh.front().delay;
        for (const auto& sample : fresh) {
            minimum = std::min(minimum, sample.delay);
            maximum = std::max(maximum, sample.delay);
        }
        return maximum - minimum;
    }

    std::size_t sample_count() const noexcept { return samples_.size(); }
    bool has_pending_query() const noexcept { return pending_.has_value(); }

private:
    struct Pending {
        awdlwin::wire::Bytes identity;
        Time submitted_at;
    };
    struct TimedSample {
        Delay delay;
        Time observed_at;
    };

    static bool valid_time(Time value) noexcept {
        return value.time_since_epoch().count() >= 0;
    }
    static bool valid_mpdu(std::span<const std::uint8_t> mpdu) noexcept {
        return mpdu.size() >= 24 && mpdu.size() <= maximum_mpdu_bytes;
    }
    static awdlwin::wire::Bytes normalized(std::span<const std::uint8_t> mpdu) {
        awdlwin::wire::Bytes identity(mpdu.begin(), mpdu.end());
        identity[22] = 0;
        identity[23] = 0;
        return identity;
    }
    bool pending_expired(Time now) const noexcept {
        return pending_ && now >= pending_->submitted_at &&
            now - pending_->submitted_at > pending_lifetime;
    }
    void expire_pending(Time now) {
        if (pending_expired(now)) {
            pending_.reset();
            invalidate_samples();
        }
    }
    std::vector<TimedSample> fresh_samples(Time now) const {
        std::vector<TimedSample> fresh;
        if (!valid_time(now)) return fresh;
        fresh.reserve(samples_.size());
        for (const auto& sample : samples_)
            if (is_fresh(sample, now)) fresh.push_back(sample);
        return fresh;
    }
    static bool is_fresh(const TimedSample& sample, Time now) noexcept {
        return now >= sample.observed_at && now - sample.observed_at <= sample_freshness;
    }
    void retain_fresh_samples(Time now) {
        samples_.erase(std::remove_if(samples_.begin(), samples_.end(), [&](const TimedSample& sample) {
            return !is_fresh(sample, now);
        }), samples_.end());
    }
    void invalidate_samples() noexcept { samples_.clear(); }

    std::optional<Pending> pending_;
    std::vector<TimedSample> samples_;
    std::optional<Time> latest_observation_;
};

} // namespace tx10ub::usb
