"""Job runner with sched and a fake clock — fixed rate, overruns, failing jobs

Not every periodic task deserves a crontab line. A long-running agent that
checks disks every minute and rotates a spool every five is a few lines with
the stdlib sched module: enter() an event, and let each job re-enter itself.
Three details decide whether it survives production:

- Re-schedule from the planned time, not from "now", or the schedule drifts
  by the job's runtime on every run (fixed rate vs fixed delay).
- When a job overruns its interval, skip the missed slots instead of firing
  them back to back to "catch up".
- A job that raises must be logged and rescheduled, not kill the loop.

sched runs events in one thread, so a slow job also delays the others; the
log marks those runs as late, which is the signal to move the job out.

sched.scheduler takes the time and sleep functions as arguments, so a fake
clock makes the whole timeline testable and instant: sleeping advances the
fake time, and a job "takes" time by advancing it too.
"""

import sched


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def time(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += max(seconds, 0.0)


class Runner:
    def __init__(self, clock: FakeClock) -> None:
        self.clock = clock
        self.scheduler = sched.scheduler(clock.time, clock.sleep)
        self.log: list[str] = []

    def every(self, interval: float, name: str, func, first: float = 0.0) -> None:
        self.scheduler.enterabs(first, 1, self._run, (interval, name, func, first))

    def _run(self, interval: float, name: str, func, planned: float) -> None:
        start = self.clock.time()
        late = f"  (late {start - planned:.0f}s)" if start > planned else ""
        try:
            result = func()
            self.log.append(f"t={start:>5.0f}  {name:<10} ok    {result}{late}")
        except Exception as exc:  # one bad run must not stop the runner
            self.log.append(f"t={start:>5.0f}  {name:<10} FAIL  {type(exc).__name__}: {exc}{late}")
        nxt = planned + interval
        now = self.clock.time()
        if nxt <= now:  # overran: skip the slots we already missed
            missed = int((now - planned) // interval)
            nxt = planned + (missed + 1) * interval
            self.log.append(f"t={now:>5.0f}  {name:<10} skip  {missed} missed run(s)")
        self.scheduler.enterabs(nxt, 1, self._run, (interval, name, func, nxt))

    def run_until(self, deadline: float) -> None:
        self.scheduler.enterabs(deadline, 0, self._stop)
        self.scheduler.run()

    def _stop(self) -> None:
        for event in list(self.scheduler.queue):
            self.scheduler.cancel(event)


def main() -> None:
    clock = FakeClock()
    runner = Runner(clock)

    disk_samples = iter([71, 72, 72, 74, 79, 83, 88, 90, 91, 91, 92])

    def disk_check():
        clock.sleep(2)  # the check itself takes 2 s
        pct = next(disk_samples)
        return f"/var at {pct}%" + ("  -> WARN" if pct >= 85 else "")

    spool_runs = iter([5, 140, 5, 5])  # second rotation hits a slow NFS mount

    def rotate_spool():
        took = next(spool_runs)
        clock.sleep(took)
        return f"rotated in {took}s"

    attempts = iter([None, "broken pipe", None])

    def push_metrics():
        err = next(attempts)
        if err:
            raise ConnectionError(err)
        return "pushed 42 series"

    runner.every(60, "disk", disk_check)
    runner.every(120, "spool", rotate_spool, first=30)
    runner.every(200, "metrics", push_metrics, first=10)
    runner.run_until(600)

    print("\n".join(runner.log))
    print(f"stopped at t={clock.time():.0f}, queue empty: {runner.scheduler.empty()}")


if __name__ == "__main__":
    main()

# Output:
# t=    0  disk       ok    /var at 71%
# t=   10  metrics    ok    pushed 42 series
# t=   30  spool      ok    rotated in 5s
# t=   60  disk       ok    /var at 72%
# t=  120  disk       ok    /var at 72%
# t=  150  spool      ok    rotated in 140s
# t=  290  spool      skip  1 missed run(s)
# t=  290  disk       ok    /var at 74%  (late 110s)
# t=  292  disk       skip  1 missed run(s)
# t=  292  metrics    FAIL  ConnectionError: broken pipe  (late 82s)
# t=  300  disk       ok    /var at 79%
# t=  360  disk       ok    /var at 83%
# t=  390  spool      ok    rotated in 5s
# t=  410  metrics    ok    pushed 42 series
# t=  420  disk       ok    /var at 88%  -> WARN
# t=  480  disk       ok    /var at 90%  -> WARN
# t=  510  spool      ok    rotated in 5s
# t=  540  disk       ok    /var at 91%  -> WARN
# stopped at t=600, queue empty: True
