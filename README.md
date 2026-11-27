# Monerod scanner research

This repository contains sanitized findings from passive IPv4 TCP research on Monero-associated ports 18080, 18081 and 18089, and a subsequent synthetic-wallet experiment.

- [Daily aggregate findings, November 23](reports/daily-2026-11-23.md)
- [Daily aggregate findings, November 24](reports/daily-2026-11-24.md)
- [Daily aggregate findings, November 25](reports/daily-2026-11-25.md)
- [Daily aggregate findings, November 26](reports/daily-2026-11-26.md)
- [Daily aggregate findings, November 27](reports/daily-2026-11-27.md)
- [Study windows and aggregate findings](FINDINGS.md)
- [Detailed findings through November 21, 2026](REPORT.md)
- [Observed scanner patterns and overlaps](indicators/scanner-patterns.json)
- [Published scanner IPv4 ranges and aggregate matches](indicators/scanner-range-matches.json)
- [Observed probe fingerprints](indicators/probe-fingerprints.json)
- [Passive TCP listener](listener/listener.py) and [offline pcapng metadata reader](pcap/pcapmeta.py)

The indicator files preserve observed labels, network associations and aggregated matches. Labels can be supplied by clients. Published-range matches associate traffic with infrastructure at the time of lookup. Neither alone identifies an operator or establishes intent.

This snapshot excludes internal sensor identifiers, fleet configuration, access details, credentials, raw captures and the original Git history. The aggregate findings come from the original collector and packet analysis. The included code and synthetic tests support local evaluation.

## Local checks

Python 3 and its standard library are sufficient.

```sh
python3 listener/test_listener.py
python3 pcap/test-meta.py
```

The listener test uses loopback and a temporary SQLite database. The metadata test generates its own pcapng fixture.

## Run the listener locally

```sh
python3 listener/listener.py
```

The listener binds to IPv4 loopback and writes a SQLite queue under the ignored `captures/` directory. Set `MONERO_SCAN_PORTS` to a comma-separated list to select different ports. Set `MONERO_SCAN_STATE` to choose another local storage directory. The queue contains peer addresses and captured request prefixes. Keep it outside version control.
