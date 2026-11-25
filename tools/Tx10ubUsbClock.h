#pragma once

#include "../src/awdl_discovery_state.h"

#include <chrono>
#include <cassert>
#include <cstdint>
#include <limits>
#include <optional>
#include <utility>
#include <variant>

namespace awdlwin::tx10ub::usb_clock {

// UTC is the Unix microsecond timestamp carried by USBPcap's packet record.
// The steady bracket is acquired by the caller around its UTC read. This pure
// bridge has no Windows clock calls and makes no claim about USB/hardware queue
// delay: it maps only the timestamped USB completion event.
struct Observation {
    std::uint64_t utc_us;
    discovery::MonotonicTime steady_before;
    discovery::MonotonicTime steady_after;
};

// These are caller-supplied acceptance assumptions, not measured guarantees.
// logger_quantization_us applies independently to the first UTC sample and an
// event UTC timestamp. maximum_clock_offset_drift_us is the assumed offset
// variation since the fixed initial reference.
struct Budget {
    std::uint64_t maximum_bracket_us;
    std::uint64_t maximum_interval_us;
    std::uint64_t maximum_clock_offset_drift_us;
    std::uint64_t maximum_event_age_us;
    std::uint64_t maximum_mapping_error_us;
    std::uint64_t logger_quantization_us;
};

// Operator-controlled capture has no fixed session lifetime. Keep the original
// clock anchor and enforce the same drift, freshness and mapping-error limits
// on every observation; only the artificial 180-second duration cap is removed.
inline constexpr Budget discovery_budget{1000,
    static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)()),
    1000,250'000,2000,1};
inline constexpr unsigned maximum_acquisition_attempts = 3;
inline constexpr std::chrono::microseconds transport_pending_lifetime{1'000'000};

enum class ClockError {
    invalid_budget,
    invalid_observation,
    bracket_too_wide,
    interval_too_long,
    utc_regressed,
    steady_regressed,
    offset_drift_exceeded,
    mapping_error_exceeded,
    event_before_start,
    event_in_future,
    event_stale,
    event_timestamp_regressed,
    unrepresentable_time
};

struct Failure { ClockError error; };
using AcquisitionResult = std::variant<Observation, Failure>;

// A wide bracket is an acquisition-quality failure that can be sampled again
// before it reaches the sticky Bridge. Invalid brackets fail immediately;
// accepted observations still go through Bridge for regression/drift checks.
template<class Acquire>
AcquisitionResult acquire_observation(Acquire&& acquire, const Budget& budget) {
    for (unsigned attempt = 0; attempt < maximum_acquisition_attempts; ++attempt) {
        auto candidate = acquire();
        const auto before = candidate.steady_before.time_since_epoch().count();
        const auto after = candidate.steady_after.time_since_epoch().count();
        if (before < 0 || before > after)
            return Failure{ClockError::invalid_observation};
        const auto width = static_cast<std::uint64_t>(after - before);
        if (width <= budget.maximum_bracket_us) return std::move(candidate);
    }
    return Failure{ClockError::bracket_too_wide};
}

struct MappedEvent {
    discovery::MonotonicTime event_at;
    std::uint64_t uncertainty_us;
};
using MappingResult = std::variant<MappedEvent, Failure>;

// The session anchor and all event mappings use the first observation's fixed
// steady midpoint. Every later observation must remain within the explicit
// clock and interval budgets; the first violation permanently halts this
// bridge. Mapping is limited to observed UTC time, event age, and the fixed
// start reference. Equal event timestamps are allowed for multiple AWDL frames
// from one USB packet; decreasing event timestamps are rejected.
class Bridge {
public:
    static auto start(Observation first, Budget budget);

    Bridge(Observation first, Budget budget) : first_(first), latest_(first), budget_(budget) {
        if (!budget_valid(budget_)) {
            failure_ = Failure{ClockError::invalid_budget};
            return;
        }
        if (!observation_valid(first_)) {
            failure_ = Failure{ClockError::invalid_observation};
            return;
        }
        const auto width = bracket_width(first_);
        if (width > budget_.maximum_bracket_us) {
            failure_ = Failure{ClockError::bracket_too_wide};
            return;
        }

        const auto before = steady_us(first_.steady_before);
        const auto midpoint = before + width / 2;
        start_ = discovery::MonotonicTime{std::chrono::microseconds{
            static_cast<std::int64_t>(midpoint)}};

        auto error = width / 2 + width % 2;
        if (!add_bounded(error, budget_.logger_quantization_us) ||
            !add_bounded(error, budget_.logger_quantization_us) ||
            !add_bounded(error, budget_.maximum_clock_offset_drift_us)) {
            failure_ = Failure{ClockError::mapping_error_exceeded};
            return;
        }
        uncertainty_us_ = error;
        if (uncertainty_us_ > budget_.maximum_mapping_error_us)
            failure_ = Failure{ClockError::mapping_error_exceeded};
    }

    bool ready() const noexcept { return !failure_.has_value(); }
    bool halted() const noexcept { return failure_.has_value(); }
    const std::optional<Failure>& failure() const noexcept { return failure_; }
    discovery::MonotonicTime session_start() const noexcept {
        assert(ready());
        return *start_;
    }

    // Returns no failure on acceptance. A clock failure is sticky: no later
    // observation can reset or resume this bridge.
    std::optional<Failure> observe(const Observation& next) noexcept {
        if (failure_) return failure_;
        if (!observation_valid(next)) return halt(ClockError::invalid_observation);

        const auto next_width = bracket_width(next);
        if (next_width > budget_.maximum_bracket_us)
            return halt(ClockError::bracket_too_wide);
        if (next.utc_us < latest_.utc_us)
            return halt(ClockError::utc_regressed);
        if (next.steady_before < latest_.steady_after)
            return halt(ClockError::steady_regressed);

        const auto first_before = steady_us(first_.steady_before);
        const auto next_after = steady_us(next.steady_after);
        const auto steady_interval = next_after - first_before;
        const auto utc_interval = next.utc_us - first_.utc_us;
        if (steady_interval > budget_.maximum_interval_us ||
            utc_interval > budget_.maximum_interval_us)
            return halt(ClockError::interval_too_long);

        const auto first_midpoint = steady_us(*start_);
        const auto next_midpoint = steady_us(next.steady_before) + next_width / 2;
        const auto steady_elapsed = next_midpoint - first_midpoint;
        const auto offset_delta = absolute_difference(steady_elapsed, utc_interval);

        // Offset comparison itself is uncertain by both bracket midpoints and
        // both quantized UTC reads. Keep those caller-declared terms explicit.
        auto tolerance = budget_.maximum_clock_offset_drift_us;
        if (!add_bounded(tolerance, bracket_uncertainty(bracket_width(first_))) ||
            !add_bounded(tolerance, bracket_uncertainty(next_width)) ||
            !add_bounded(tolerance, budget_.logger_quantization_us) ||
            !add_bounded(tolerance, budget_.logger_quantization_us) ||
            offset_delta > tolerance)
            return halt(ClockError::offset_drift_exceeded);

        latest_ = next;
        return std::nullopt;
    }

    // Outbound transport observations share this coordinate system, but must
    // not consume or regress the independent inbound event cursor.
    MappingResult map_sample(std::uint64_t event_utc_us) const noexcept {
        return map_sample_with_age(event_utc_us, budget_.maximum_event_age_us);
    }

    // USB OUT records are matched only to a still-pending exact TX identity.
    // Their queue age may exceed the RX freshness budget, but is bounded by
    // that identity's existing pending lifetime.
    MappingResult map_transport_sample(std::uint64_t event_utc_us) const noexcept {
        return map_sample_with_age(event_utc_us,
            static_cast<std::uint64_t>(transport_pending_lifetime.count()));
    }

    MappingResult map_event(std::uint64_t event_utc_us) noexcept {
        auto mapped=map_sample(event_utc_us);
        if(!std::holds_alternative<MappedEvent>(mapped))return mapped;
        if (last_event_utc_us_ && event_utc_us < *last_event_utc_us_)
            return Failure{ClockError::event_timestamp_regressed};
        if(std::holds_alternative<MappedEvent>(mapped))last_event_utc_us_=event_utc_us;
        return mapped;
    }

    // No future accepted event can be older than this coordinate: observe()
    // requires nondecreasing UTC and map_event() enforces maximum_event_age_us.
    // This does not consume an event or change its regression cursor.
    MappingResult minimum_future_event_time()const noexcept {
        if(failure_)return *failure_;
        auto utc=latest_.utc_us>budget_.maximum_event_age_us?
            latest_.utc_us-budget_.maximum_event_age_us:0;
        if(utc<first_.utc_us)utc=first_.utc_us;
        return coordinate(utc);
    }

private:
    MappingResult map_sample_with_age(std::uint64_t event_utc_us,
                                      std::uint64_t maximum_age_us) const noexcept {
        if (failure_) return *failure_;
        if (event_utc_us < first_.utc_us) return Failure{ClockError::event_before_start};
        if (event_utc_us > latest_.utc_us) return Failure{ClockError::event_in_future};
        if (latest_.utc_us - event_utc_us > maximum_age_us)
            return Failure{ClockError::event_stale};
        return coordinate(event_utc_us);
    }
    MappingResult coordinate(std::uint64_t utc)const noexcept {
        const auto delta = utc - first_.utc_us;
        constexpr auto max_time = static_cast<std::uint64_t>(
            (std::numeric_limits<std::int64_t>::max)());
        const auto start_us = steady_us(*start_);
        if (delta > max_time || start_us > max_time - delta)
            return Failure{ClockError::unrepresentable_time};

        return MappedEvent{
            discovery::MonotonicTime{std::chrono::microseconds{
                static_cast<std::int64_t>(start_us + delta)}},
            uncertainty_us_};
    }

    static constexpr std::uint64_t max_time_us() noexcept {
        return static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)());
    }
    static std::uint64_t steady_us(discovery::MonotonicTime value) noexcept {
        return static_cast<std::uint64_t>(value.time_since_epoch().count());
    }
    static bool observation_valid(const Observation& observation) noexcept {
        return observation.steady_before.time_since_epoch().count() >= 0 &&
               observation.steady_before <= observation.steady_after;
    }
    static std::uint64_t bracket_width(const Observation& observation) noexcept {
        return steady_us(observation.steady_after) - steady_us(observation.steady_before);
    }
    static std::uint64_t bracket_uncertainty(std::uint64_t width) noexcept {
        return width / 2 + width % 2;
    }
    static std::uint64_t absolute_difference(std::uint64_t left,
                                             std::uint64_t right) noexcept {
        return left >= right ? left - right : right - left;
    }
    static bool add_bounded(std::uint64_t& total, std::uint64_t add) noexcept {
        if (add > max_time_us() - total) return false;
        total += add;
        return true;
    }
    static bool budget_valid(const Budget& budget) noexcept {
        return budget.maximum_bracket_us <= max_time_us() &&
               budget.maximum_interval_us <= max_time_us() &&
               budget.maximum_clock_offset_drift_us <= max_time_us() &&
               budget.maximum_event_age_us <= max_time_us() &&
               budget.maximum_mapping_error_us <= max_time_us() &&
               budget.logger_quantization_us <= max_time_us();
    }
    std::optional<Failure> halt(ClockError error) noexcept {
        failure_ = Failure{error};
        return failure_;
    }

    Observation first_;
    Observation latest_;
    Budget budget_;
    std::optional<discovery::MonotonicTime> start_;
    std::uint64_t uncertainty_us_ = 0;
    std::optional<std::uint64_t> last_event_utc_us_;
    std::optional<Failure> failure_;
};

using StartResult = std::variant<Bridge, Failure>;

inline auto Bridge::start(Observation first, Budget budget) {
    Bridge candidate(first, budget);
    if (candidate.ready())
        return StartResult{std::in_place_index<0>, std::move(candidate)};
    return StartResult{std::in_place_index<1>, *candidate.failure()};
}

} // namespace awdlwin::tx10ub::usb_clock
