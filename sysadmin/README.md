# sysadmin — Python for server and network operations

Scripts I wrote while studying Python for day-to-day server and network work. The topic list follows the chapters of *시스템/네트워크 관리자를 위한 파이썬 실무 프로그래밍* (Wikibooks); the code here is my own and grew the way real admin tools do — a first version, then fixes once it met real output.

Device and command output (MegaCLI, `ipmitool`, `snmpwalk`, `show cdp neighbors`, `vmstat`, `auth.log` …) is embedded as sample text, so every example runs offline on a laptop.

```bash
python3 sysadmin/<topic>/<example>.py      # every example runs on its own
python3 scripts/check.py sysadmin          # run all and compare with the # Output: blocks
```

11 examples, checked on Python 3.13.

## host

Collecting host facts and parsing `/proc/meminfo`, `df`, `vmstat` and `iostat` into reports (CSV and a hand-written .xlsx).

| Example | Notes |
| --- | --- |
| [`df_parse.py`](host/df_parse.py) | Parsing `df -h` — wrapped lines, human sizes and mount points with spaces |
| [`meminfo_parse.py`](host/meminfo_parse.py) | Parsing /proc/meminfo — use MemAvailable, not MemFree |
| [`system_inventory.py`](host/system_inventory.py) | System inventory with platform, os and shutil — collect live, report from data |

## logs

Searching and following logs like `grep`/`tail -F`, colored severity output, `logging` handlers and failure alerts.

| Example | Notes |
| --- | --- |
| [`log_search.py`](logs/log_search.py) | log_search v2 — argparse front end, several keywords, grep-style exit codes |

## remote

Talking to other hosts: TCP health checks, exception handling that tells failures apart, retries and `subprocess`.

| Example | Notes |
| --- | --- |
| [`tcp_health_check.py`](remote/tcp_health_check.py) | TCP health check — tell "refused", "timeout" and "no such host" apart |

## schedule

Running things on time: `sched`, cron expressions and next-run times, Bash interop and lock files for cron jobs.

| Example | Notes |
| --- | --- |
| [`sched_runner.py`](schedule/sched_runner.py) | Job runner with sched and a fake clock — fixed rate, overruns, failing jobs |

## hardware

RAID controller reports, IPMI sensors, SEL events, fan monitoring and support bundles.

| Example | Notes |
| --- | --- |
| [`megacli_raid_report.py`](hardware/megacli_raid_report.py) | MegaCLI RAID report v2: virtual drives, physical disk errors and rebuilds |

## network

SNMP OIDs and a small BER codec, counter deltas and wrap, utilization graphs, CDP/MAC tables to config, CoPP, EEM-style rules, config diffs.

| Example | Notes |
| --- | --- |
| [`interface_counter_delta.py`](network/interface_counter_delta.py) | Interface counters v2: Counter32 vs Counter64 deltas, bps and utilization |
| [`snmp_oid_names.py`](network/snmp_oid_names.py) | SNMP: translate numeric OIDs to IF-MIB names and back, without net-snmp MIBs |

## history

Shell history and login records: what accounts run, when, and which commands are risky.

| Example | Notes |
| --- | --- |
| [`history_timestamps.py`](history/history_timestamps.py) | Shell history with HISTTIMEFORMAT: '#<epoch>' lines, sessions, night work |
| [`history_top_commands.py`](history/history_top_commands.py) | Shell history: which commands does this account actually run? |
