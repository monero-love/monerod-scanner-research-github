# Study windows and aggregate findings

All study windows use UTC and exclude the end time. The cumulative windows begin with the first listener event on October 30, 2026 at 19:50 UTC. The packet archive begins later that day at 22:35 UTC.

| Listener window (UTC) | Connections | Distinct source addresses |
| --- | ---: | ---: |
| October 31 at 20:02:47.930083 to November 3 at 20:02:47.930083 | 8,540 | 1,673 |
| November 6 at 00:00 to November 13 at 00:00 | 14,634 | 3,314 |
| Cumulative through November 13 at 18:44 | 32,231 | 4,686 |
| Cumulative through November 21 at 16:10 | 50,451 | 6,412 |

The windows overlap and cannot be added.

## Initial 72-hour study

One source, labeled S0065 within the snapshot, sent 19 `get_version` requests across 14 sensors. Sixteen requests reached port 18089 and three reached port 18081. Ten sensors received requests within 20.43 seconds on November 1. The client declared `curl/8.5.0`. The operator is unidentified and an unmarked test remains possible.

During the same window, 623 of 1,673 source addresses also appeared in logs for other honeypot services. Seven addresses accounted for 166 accepted logins on a simulated SSH service. Those sessions showed no recorded shell commands or file transfers. Two later cross-service queries timed out, leaving the extent of subsequent overlap unknown.

## Subsequent synthetic wallet pilot

Updated through 2026-11-25 02:33:08.458644 UTC, exclusive: 1547 cumulative records, 96 marked validation exchanges excluded, and 1451 unmarked connections. The twelve-sensor experiment recorded 26 unmarked `get_info` requests with method-not-found response buffers. One unmarked `get_balance` request produced a recorded synthetic 10 XMR reply. Its origin is unverified. No account, address, key or spending requests were parsed. Cohorts activated at different times. See the [daily report](reports/daily-2026-11-25.md).
