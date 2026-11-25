namespace DropPorter.Wpf;

// The known-byte ETA used by CopyPilot, with time measured on a monotonic clock.
internal sealed class TransferEta
{
    private const double RateWindow = 10, RecentWindow = 2, MinimumHistory = 1, ConfirmationTime = 4;
    private readonly record struct Interval(double Start, double End, ulong Bytes);
    private readonly Queue<Interval> intervals = new();
    private double? lastTime;
    private ulong lastBytes;
    private double? displayed;
    private double displayTime, directionSince;
    private int direction;
    private double? overestimateSince;

    internal void Reset()
    {
        intervals.Clear();
        lastTime = displayed = overestimateSince = null;
        direction = 0;
    }

    internal double? Update(double now, ulong bytes, ulong total)
    {
        if (bytes >= total || bytes < lastBytes || now < lastTime) Reset();
        if (now == lastTime) return displayed;
        var previous = lastTime;
        var delta = previous.HasValue ? bytes - lastBytes : 0;
        lastTime = now;
        lastBytes = bytes;
        if (bytes >= total || previous is not double start) return displayed;

        intervals.Enqueue(new(start, now, delta));
        while (intervals.Peek().End <= now - RateWindow) intervals.Dequeue();
        if (delta == 0 && displayed.HasValue)
        {
            displayTime = now;
            return displayed;
        }

        double duration = 0, moved = 0, recentDuration = 0, recentMoved = 0;
        foreach (var interval in intervals)
        {
            var seconds = interval.End - interval.Start;
            var overlap = interval.End - Math.Max(interval.Start, now - RateWindow);
            var recent = Math.Max(0, interval.End - Math.Max(interval.Start, now - RecentWindow));
            duration += overlap;
            moved += interval.Bytes * (overlap / seconds);
            recentDuration += recent;
            recentMoved += interval.Bytes * (recent / seconds);
        }
        if (duration < MinimumHistory || moved <= 0 || delta == 0) return null;
        var rate = moved / duration;
        var target = Math.Clamp((total - bytes) / rate, 1, TimeSpan.MaxValue.TotalSeconds - 1);
        var recentRatio = recentDuration > 0 ? recentMoved / recentDuration / rate : 0;
        var confirmed = recentDuration >= MinimumHistory && recentRatio is >= (2d / 3) and <= 1.5;
        if (displayed is double prior)
        {
            var elapsed = now - displayTime;
            var projected = Math.Max(0, prior - elapsed);
            var error = target - projected;
            var nextDirection = Math.Abs(error) <= Math.Max(1, projected * .015) ? 0 : Math.Sign(error);
            if (direction != nextDirection)
            {
                direction = nextDirection;
                directionSince = now;
            }
            if (confirmed && target <= Math.Max(1, projected) * (2d / 3))
                overestimateSince ??= now;
            else
                overestimateSince = null;
            if (overestimateSince is double since && now - since >= ConfirmationTime)
            {
                direction = 0;
                overestimateSince = null;
            }
            else
            {
                var limit = Math.Clamp(prior * .02, 2, 5) * Math.Min(elapsed, 1);
                var correction = direction != 0 && now - directionSince >= ConfirmationTime
                    ? Math.Clamp(error * (1 - Math.Exp(-elapsed / 3)), -limit, limit) : 0;
                target = Math.Max(1, projected + correction);
            }
        }
        displayTime = now;
        return displayed = target;
    }
}
