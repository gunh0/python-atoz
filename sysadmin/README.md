# sysadmin — Python for server and network operations

Scripts I wrote while studying Python for day-to-day server and network work. The topic list follows the chapters of *시스템/네트워크 관리자를 위한 파이썬 실무 프로그래밍* (Wikibooks); the code here is my own and grew the way real admin tools do — a first version, then fixes once it met real output.

Device and command output (MegaCLI, `ipmitool`, `snmpwalk`, `show cdp neighbors`, `vmstat`, `auth.log` …) is embedded as sample text, so every example runs offline on a laptop.

```bash
python3 sysadmin/<topic>/<example>.py      # every example runs on its own
python3 scripts/check.py sysadmin          # run all and compare with the # Output: blocks
```

24 examples, checked on Python 3.13, Python 3.14.

## host

Collecting host facts and parsing `/proc/meminfo`, `df`, `vmstat` and `iostat` into reports (CSV and a hand-written .xlsx).

| Example | Notes |
| --- | --- |
| [`df_parse.py`](host/df_parse.py) | Parsing `df -h` — wrapped lines, human sizes and mount points with spaces |
| [`meminfo_parse.py`](host/meminfo_parse.py) | Parsing /proc/meminfo — use MemAvailable, not MemFree |
| [`system_inventory.py`](host/system_inventory.py) | System inventory with platform, os and shutil — collect live, report from data |
| [`vmstat_parse.py`](host/vmstat_parse.py) | Parsing `vmstat 1 5` — read columns by header name, drop the boot line |
| [`vmstat_report.py`](host/vmstat_report.py) | vmstat report v2 — also write a real .xlsx by hand with zipfile and XML |

## logs

Searching and following logs like `grep`/`tail -F`, colored severity output, `logging` handlers and failure alerts.

| Example | Notes |
| --- | --- |
| [`log_search.py`](logs/log_search.py) | log_search v3 — --since/--until time ranges over syslog and ISO timestamps |
| [`severity_colors.py`](logs/severity_colors.py) | Colored severity output with ANSI escapes — and when not to emit them |

## remote

Talking to other hosts: TCP health checks, exception handling that tells failures apart, retries and `subprocess`.

| Example | Notes |
| --- | --- |
| [`connect_helper.py`](remote/connect_helper.py) | connect_helper, first fix — narrow except, close the socket, still lossy |
| [`tcp_health_check.py`](remote/tcp_health_check.py) | TCP health check — tell "refused", "timeout" and "no such host" apart |

## schedule

Running things on time: `sched`, cron expressions and next-run times, Bash interop and lock files for cron jobs.

| Example | Notes |
| --- | --- |
| [`cron_expr.py`](schedule/cron_expr.py) | cron_expr v1 — parse a five-field cron expression into explicit value sets |
| [`sched_runner.py`](schedule/sched_runner.py) | Job runner with sched and a fake clock — fixed rate, overruns, failing jobs |

## hardware

RAID controller reports, IPMI sensors, SEL events, fan monitoring and support bundles.

| Example | Notes |
| --- | --- |
| [`fan_monitor.py`](hardware/fan_monitor.py) | Fan monitor v1: `ipmitool sdr type Fan` across hosts with our own RPM policy |
| [`ipmi_sensor_thresholds.py`](hardware/ipmi_sensor_thresholds.py) | IPMI: parse `ipmitool sensor` and check readings against BMC thresholds |
| [`megacli_raid_report.py`](hardware/megacli_raid_report.py) | MegaCLI RAID report v2: virtual drives, physical disk errors and rebuilds |
| [`support_bundle_tar.py`](hardware/support_bundle_tar.py) | Support bundle: collect hardware logs into a .tar.gz safely with tarfile |

## network

SNMP OIDs and a small BER codec, counter deltas and wrap, utilization graphs, CDP/MAC tables to config, CoPP, EEM-style rules, config diffs.

| Example | Notes |
| --- | --- |
| [`cdp_neighbors_description.py`](network/cdp_neighbors_description.py) | CDP neighbors -> `interface ... / description ...` config lines |
| [`interface_counter_delta.py`](network/interface_counter_delta.py) | Interface counters v2: Counter32 vs Counter64 deltas, bps and utilization |
| [`mac_table_description.py`](network/mac_table_description.py) | Access-port descriptions from `show mac address-table` + an inventory map |
| [`snmp_oid_names.py`](network/snmp_oid_names.py) | SNMP: translate numeric OIDs to IF-MIB names and back, without net-snmp MIBs |
| [`utilization_sparkline.py`](network/utilization_sparkline.py) | Link utilization in the terminal: sparklines and a bar graph from counters |

## history

Shell history and login records: what accounts run, when, and which commands are risky.

| Example | Notes |
| --- | --- |
| [`history_per_user.py`](history/history_per_user.py) | Shell history per user: aggregate bash and zsh history files from one host |
| [`history_timestamps.py`](history/history_timestamps.py) | Shell history with HISTTIMEFORMAT: '#<epoch>' lines, sessions, night work |
| [`history_top_commands.py`](history/history_top_commands.py) | Shell history: which commands does this account actually run? |
| [`risky_commands.py`](history/risky_commands.py) | Shell history audit: flag risky commands and redact credentials in the report |
