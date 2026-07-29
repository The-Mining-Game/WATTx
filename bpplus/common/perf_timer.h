// Minimal stub of Monero's common/perf_timer.h — no-op timers for the isolated
// libwattx_bpplus port (BP+ prove/verify don't need real perf instrumentation).
#pragma once
#define PERF_TIMER(name) do {} while (0)
#define PERF_TIMER_UNIT(name, unit) do {} while (0)
#define PERF_TIMER_START_UNIT(name, unit) do {} while (0)
#define PERF_TIMER_STOP(name) do {} while (0)
#define PERF_TIMER_START(name) do {} while (0)
