# What the span data changed

There is no Sentry project behind this repository and no DSN, so the
instrumentation runs in its offline mode: the same spans open, the same
transaction payloads are built and scrubbed, and they are written to
`data/sentry/` instead of being transmitted. The timings below are that
mode's own output, read back from `data/sentry/spans.json`. Nothing here is
an estimate.

## The problem, as the spans reported it

`ReplayEngine` paces a replay in simulated log-hours per wall-clock second.
The default for the demo is 6, so one day of logs should take four seconds.
The paced loop carries counters rather than a span per wait, because a
replay waits tens of thousands of times and a span each would cost more than
the sleep it was measuring. The counters land on `stream.replay`:

```
pace.waits          481
pace.requested_ms   7008
pace.actual_ms      11860
```

Replaying 13 and 14 March, 1,051 events spanning 43.94 log hours, at 6 hours
per second:

| | wall clock | should be | drift |
|---|---|---|---|
| before | 11.88 s | 7.32 s | **+62.2%** |
| after | 7.33 s | 7.32 s | **+0.1%** |

At 30 hours per second the same change moves the drift from -8.6% to -0.1%.

A replay advertising six log-hours per second was delivering about four. The
clock on screen was right, because the cursor follows the log's own
timestamps; the rate was not.

## Why

Two causes, and only one of them was already handled.

The first is the platform timer. `threading.Event.wait` on this machine
rounds up to a 16 ms tick:

```
requested   2.0ms -> median  16.00ms
requested   5.0ms -> median  16.00ms
requested  10.0ms -> median  16.00ms
requested  15.0ms -> median  16.00ms
```

`MIN_SLEEP_S = 0.002` was already in the engine for exactly this reason, and
it works: a sub-millisecond gap is emitted immediately rather than costing a
full tick. But 63% of the gaps at demo speed compute to under 2 ms and take
that path, while the remaining 37% land in the 2 to 15 ms band, where the
floor does nothing and every single wait still pays a whole tick. Measured
overshoot was 10.09 ms per wait.

The second cause is the one that turned a constant overhead into a
compounding one. Each event's deadline was set as `clock() + delay`, which
measures the gap from the moment the previous event *actually came out*. So
a wait that overran by 10 ms pushed the next deadline 10 ms later, and the
one after that, for 481 waits.

## The fix

`ReplayEngine._schedule` anchors each deadline on the previous deadline
rather than on the clock, so an overrun is absorbed by the next gap instead
of being added to it. `MAX_CATCHUP_S` bounds how far behind the schedule may
fall, which is what stops a paused replay from sprinting through a backlog
when it resumes.

Commit: `fix(replay): schedule each event from the last deadline`.
Regression test: `test_pacing_absorbs_an_overrun_instead_of_compounding_it`
in `tests/test_replay.py`, driven by a fake clock so it does not depend on
the timer that caused the problem.

## What did not change

Wall-clock emission timing, and nothing else. Event order, log timestamps,
alerts, incidents, metrics and the case file are not functions of when the
emitting thread woke up, and the evaluation harness runs with `fast=True`,
which skips pacing entirely. The 240 tests pass before and after, with the
same numbers.

## Limitations

This is one machine's timer. On a platform with a 1 ms scheduler tick the
overshoot per wait would be smaller and the compounding correspondingly
slower, but the compounding itself is structural and would still be there.

The measurement is a two-day slice rather than the full March window,
because the full window at demo speed takes two minutes per run and the
effect is already unambiguous at 43.94 log hours. The numbers above come
from an alternating before and after run in the same process, so the
comparison is not across machine states.

This is a fix to a performance defect found by instrumenting, which is what
the exercise asks for. It is not a production incident and is not presented
as one.
