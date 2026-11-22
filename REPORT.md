# Monero-port honeypot reanalysis through November 21, 2026

Research cutoff: **2026-11-21 16:10:00 UTC**, exclusive. Prepared from fresh read-only collector exports and offline packet analysis on November 21.

## Findings that change the previous account

The cumulative listener export now contains **50,451 nonvalidation connections from 6,412 source addresses across 26 historical sensors**. The packet archive contains **709,409 packets**, of which **706,925** belong to nonvalidation traffic involving the local Monero listener ports. TShark groups that research traffic into **113,387 TCP streams from 7,156 source addresses across 25 capture sensors**.

The new interval begins at the previous cutoff, November 13 at 18:44 UTC, and ends November 21 at 16:10 UTC. It contributes **18,218 listener connections from 3,948 source addresses**, including 1,726 addresses absent from the earlier window. The simple difference between published totals is 18,220 because the fresh export also contains two late-arriving records whose event times precede the earlier cutoff. None of the old event IDs is missing. The distinction is small numerically but essential for a reproducible comparison.

Three changes deserve particular attention:

- Wallet-oriented requests now include 28 `get_address` calls and two `get_accounts` calls, alongside seven additional `get_balance` calls. All of those new wallet calls have packet corroboration. The November 20 account and address queries have unverified origin. They must not be described as confirmed independent attacker traffic.
- Fifteen HTTP requests on November 18 contain 8,132 to 8,135 reconstructed client bytes. These are the first unflagged requests above 4 KiB in this comparison. The listener retained exactly the first 4,096 bytes of each, while the packet captures preserve the longer request. They target a Vite-associated internal path and contain JavaScript-like expressions. No application response or successful execution is observed.
- Three listener feeds stopped producing current records around November 19, while their packet captures continued. All 25 packet sensors report fresh capturing health, but only 23 of 26 listener heartbeats are current. Raw daily listener counts therefore understate activity on those three sensors near the end of the study.

The underlying conclusion remains bounded: these passive endpoints receive broad service discovery, Monero-specific requests and crafted HTTP traffic. The observed exchanges contain no server application payload. They do not demonstrate wallet disclosure, transaction surveillance, successful exploitation or a compromised Monero daemon.

## Collection scope and exclusions

The requested database window starts October 30 at 00:00 UTC. The first actual listener event is later that day at 19:50 UTC. The first archived packet is at 22:35:43.871785 UTC. The latest included packet is November 21 at 16:09:11.177883 UTC. The archive manifest was collected at 16:11:06.477947 UTC, after the fixed cutoff, and the decoder filters packets against the cutoff independently.

The listener query returned 50,607 records, including 156 marked validation records. The research export excludes those 156. Packet classification excludes 78 validation streams containing 645 packets. Untagged operator requests may remain.

The sensors accept TCP connections on 18080, 18081 and 18089, retain up to 4 KiB of initial input over at most five seconds, and send no application response. They are not Monero daemons, wallet RPC services or transaction relays. The original 20-sensor cohort accounts for 39,878 connections from 5,577 addresses. Later additions have shorter observation windows. One listener has no packet capture. These different denominators prevent a direct application-log versus packet-log loss estimate.

No external scanner was probed. No captured command or JavaScript was executed. No address or URL embedded in a payload was contacted. This work did not change listeners, firewalls, capture services or retention settings.

## Connection accounting and temporal comparison

| Destination port | Previous published total | Reexport of previous window | New interval | Current cumulative total |
| --- | --- | --- | --- | --- |
| 18080 | 22,381 | 22,381 | 12,142 | 34,523 |
| 18081 | 7,018 | 7,018 | 4,681 | 11,699 |
| 18089 | 2,832 | 2,834 | 1,395 | 4,229 |
| Total | 32,231 | 32,233 | 18,218 | 50,451 |

The new interval lasts 189 hours and 26 minutes. Its 18,218 records correspond to roughly 96.2 accepted connections per wall-clock hour across the recorded fleet. That is an observed total divided by elapsed time, not a rate normalized for sensor uptime. Missing listener reporting, late delivery, sensor additions and unknown untagged tests prevent interpreting it as a clean change in internet-wide scanning intensity.

Across the cumulative export, 3,055 source addresses reached more than one sensor and 23 reached at least 20. An address is not an operator count. A scanner can use many addresses, a proxy can represent many clients and an address can change ownership.

November 21 is only a partial day. It contains 2,169 listener records from 687 source addresses through the cutoff. November 20 and 21 each have records from 23 listener sensors. Comparing either day directly with an earlier complete 26-sensor day would hide a coverage change.

The five listener labels total 25,326 other payloads, 9,515 HTTP-like requests, 8,385 TLS candidates, 5,898 empty captures and 1,327 Levin signatures. Of the HTTP-labelled rows, 1,271 have RTSP request lines and 495 have SIP request lines. Thus at least 18.56% of that label is not HTTP. The initial classifier recognizes broad patterns and must not substitute for protocol parsing.

## Archive integrity and packet accounting

The archive inventory contains 767,794 files, 311,492,148 bytes and 709,409 packets. Most one-minute files are empty. Every one of the 31,544 nonempty files was downloaded into ignored private evidence storage. The copies total 91,560,464 bytes. Every recorded byte length and SHA-256 hash matched. Empty files were inventoried through database metadata and were not individually downloaded.

Per-sensor files were merged and decoded with TShark 4.7.4. Capinfos independently counted the merged packets. The decoder, Capinfos and archive metadata all agree on 709,409 packets. No packet in this export fell at or after the cutoff.

The accounting identity is:

**709,409 archived packets = 706,925 research packets + 645 validation packets + 1,839 packets outside the local listener-port scope.**

The last category includes two packets that do not match the current sensor-address mapping. Those two remain outside the research totals. The rest illustrate the same filter caveat as before: a capture expression containing `port 18081` matches either endpoint. A remote source port can match even when the local service is SSH or another honeypot service. Direction and local destination must be established before attributing responses to a Monero listener.

Research stream counts by local port are 59,104 on 18080, 30,234 on 18081 and 24,049 on 18089. They total 113,387. These are TShark stream groupings, not accepted application connections and not independent attacks. They cannot be added to the 50,451 listener records.

The packet dataset has 956 source addresses absent from the complete listener export. The listener dataset has 212 addresses absent from the packet export. Different coverage and collection behavior contribute to both differences. Neither is an estimate of packet loss.

## TCP behavior and reassembly limits

| Packet-stream observation | Streams |
| --- | --- |
| Incoming SYN observed | 113,145 |
| Complete SYN, SYN/ACK and matching ACK observed | 74,029 |
| SYN and SYN/ACK without verified completion | 38,549 |
| Incoming SYN without observed SYN/ACK | 567 |
| Complete handshake without client payload | 6,374 |
| At least one incoming payload segment | 79,333 |
| More than one distinct incoming payload segment | 8,907 |
| Multiple coarse payload classes | 4,787 |
| Any outgoing application payload | 0 |

The rows overlap. A complete handshake can be followed by an incoming reset. A stream with payload can lack a captured handshake. The short listener timeout also influences FINs and resets. These observations do not warrant classifying every incomplete exchange as a failed attack.

TShark marks 30,337 packets across 14,853 streams as suspected retransmissions, 1,280 streams as containing out-of-order traffic and 904 as containing missing preceding segments. Those are decoder heuristics. They do not measure interface loss.

The bounded reconstruction finds conflicting bytes at shared sequence positions in 6,811 streams, gaps in 640 and segments outside its chosen sequence window in 1,720. Counts overlap. For those cases, the original packets and distinct payload segments remain the evidence. A concatenated reconstruction cannot safely be treated as an ordinary complete message. Repeated protocol templates can still be recognized in an individual segment without pretending the entire stream is unambiguous.

RPC parsing in the earlier helper considered individual payload segments. That undercounts requests whose HTTP headers and JSON body occupy different segments. This reanalysis also parses unambiguous reconstructed client streams and deduplicates each method within a sensor/stream pair. It finds 262 packet-confirmed `get_info` requests, compared with 252 in the segment-only diagnostic. It also recovers the split November 20 wallet queries. The RPC table uses the reconstructed-stream counts.

## Monero messages and RPC requests

The listener export contains 1,327 Levin-signature records from 816 addresses. Their command IDs are 510 handshake candidates and 817 ping candidates. Packet reconstruction finds 1,303 Levin messages with complete 33-byte headers and matching declared body lengths. All 1,303 are free of reconstruction gaps, conflicts and sequence-window caps. This is framing validation, not a complete semantic decoder or proof of a successful Monero peer exchange.

The frozen 259-byte handshake is still present. It appears in 416 listener connections from 194 addresses and 412 packet streams from 190 addresses. Every packet copy completed the observed TCP handshake. The embedded time remains January 31, 2021 at 11:24:20 UTC. An unchanged timestamp in identical bytes supports canned-template reuse, not incorrect current clocks on the sending systems.

| Method | Listener records | Listener source addresses | New-interval records | Packet-confirmed streams |
| --- | --- | --- | --- | --- |
| `get_accounts` | 2 | 1 | 2 | 2 |
| `get_address` | 28 | 1 | 28 | 28 |
| `get_balance` | 18 | 4 | 7 | 18 |
| `get_info` | 266 | 100 | 111 | 262 |
| `get_version` | 32 | 6 | 13 | 32 |
| `web3_clientVersion` | 7 | 7 | 5 | 7 |

The method names are checked against the [Monero daemon RPC documentation](https://docs.getmonero.org/rpc-library/monerod-rpc/) and [wallet RPC documentation](https://docs.getmonero.org/rpc-library/wallet-rpc/). `get_info` and `get_version` can identify daemon behavior. `get_balance`, `get_accounts` and `get_address` describe wallet-oriented requests. `web3_clientVersion` belongs to a different RPC ecosystem and illustrates cross-service discovery on these ports.

All packet-confirmed RPC streams in the table have an observed complete TCP handshake. The passive endpoints still sent no application replies. A valid JSON body establishes the request content, not a successful call.

### Balance requests

The cumulative 18 balance requests come from four addresses and reach seven sensors, all on 18081. Eleven were already in the November 4 cluster. Seven more occur in the new interval. The latest listener balance request is November 16 at 19:16:05.842132 UTC. The old two-address finding remains historical evidence, but it is no longer the complete source population for the study.

### Account and address requests with uncertain origin

The two `get_accounts` requests arrive on November 20 at approximately 14:07:08 UTC, reaching one sensor on both 18081 and 18089. The 28 `get_address` requests arrive from 19:29:41 to 19:32:18 UTC and reach two sensors. Fourteen use each port. They request account index zero and declare Python's urllib user agent.

Twenty-four address requests carry a Basic Authorization header and four do not. The repeated requests with changing authentication material are consistent with credential testing. They do not prove that any credential was accepted. The listener does not authenticate clients or return wallet data. Credentials are not reproduced in this report or the article.

These November 20 requests are not marked as validation. The operator could not confirm whether tests were run. They remain in the explicit nonvalidation population, with origin unresolved. Treating them as confirmed criminal activity would exceed the evidence. The raw records remain available privately if an operator test log later permits reconciliation.

## Requests longer than the listener prefix

Fifteen streams on November 18, from five addresses across seven sensors, carry 8,132 to 8,135 client bytes on port 18080. Their first observed packet times range from 04:08:05 to 23:17:47 UTC. Every stream completed TCP setup and reconstructs without gaps, conflicting bytes or sequence caps.

Each contains an HTTP GET aimed at a Vite development-server mechanism with encoded JavaScript-like expressions. The path and expressions justify describing these as crafted requests aimed at a development-server mechanism. This study has not reproduced them against Vite or established a specific vulnerability identifier, payload objective or working exploit chain.

For each of the 15 streams, the corresponding listener record contains exactly 4,096 bytes matching the start of the reconstructed request. That is direct evidence of the listener's prefix limit. The earlier negative observation that no unflagged stream exceeded 4 KiB no longer applies to the cumulative dataset.

The captures show zero server application bytes for these requests. There is no observed execution, downloaded second stage, shell, response body or credential disclosure on these passive endpoints. The requests were inspected as bytes only.

## Reused scanner templates and infrastructure associations

The exact 17-byte MQTT probe published in [LZR's source](https://github.com/stanford-esrg/lzr/blob/master/handshakes/mqtt/handshake.go) appears in 2,069 streams from 36 addresses across 23 sensors. The `lzrORA` marker appears in 2,151 streams from the same-sized address and sensor populations. These sets overlap and cannot be added. LZR's [project documentation](https://github.com/stanford-esrg/lzr) explains its use in discovering unexpected services on unexpected ports. A template match does not attribute the operator to the project's authors.

The captures also contain SSH banners, TLS candidates, HTTP, RTSP, SIP, SMB negotiation candidates, Redis probes and RDP-associated cookie markers. Nmap's distinctive probe path appears in 136 streams from 116 addresses across all 25 packet sensors. Public template reuse can connect payload families without identifying the people running them.

Operator range pages were fetched afresh on November 21 and retained with URL, retrieval time and SHA-256 hashes. Source addresses were compared with the IPv4 CIDRs on those pages. These are current-list matches, not proof of historical routing or customer identity.

| Published IPv4 range list | Listener connections | Packet streams | Packet source addresses |
| --- | --- | --- | --- |
| Palo Alto | 4,066 | 4,913 | 708 |
| Driftnet | 14,109 | 14,011 | 888 |
| Censys | 2,789 | 3,062 | 342 |
| Modat | 3,690 | 3,728 | 104 |

All 194 listener addresses and all 190 packet addresses sending the frozen Levin template match the published Palo Alto Networks ranges. The 585 streams carrying a Palo Alto Networks user-agent name come from 421 addresses, all of which also match those ranges. Together, the range match, return-path handshake and repeated payload support an infrastructure association with Cortex Xpanse. They do not identify an employee, customer or purpose behind a particular probe.

The primary sources are [Palo Alto Networks' scanning activity reference](https://cortex-docs.paloaltonetworks.com/cortex-xpanse/reference/scanning-activity), [Internet Measurement's Driftnet identification and ranges](https://internet-measurement.com/), [Censys' collection reference](https://docs.censys.com/docs/opt-out-of-data-collection) and [Modat's published IPv4 list](https://scanner.modat.io/ipv4.txt). These matches must not be converted into accusations that every probe from the ranges is malicious.

The `cryptohunt/2.0` cluster remains 58 streams across 20 sensors from November 8 through 10. It has not grown in the refreshed packet data. Names such as Infrawatch, Apcosys and zern remain self-declared labels unless corroborated separately. Hosting-network enrichment is not actor attribution. This analysis establishes no criminal-group, state-actor or transaction-surveillance attribution.

## Coverage defects and their impact

At inventory collection, 23 listener heartbeats are roughly one to two minutes old. The other three are about 216,100 seconds old, or 60 hours.

The three sensors together have 1,788 captured streams after their last listener record, including 1,320 streams carrying client payload. That demonstrates ongoing network activity that the listener export does not represent at the same time. It does not, by itself, identify whether the listener process, forwarding path, indexing pipeline or health publisher caused the discrepancy. No repair was attempted as part of this analysis.

All 25 packet sensors report `capturing`, with health records less than 30 seconds old at the inventory query. Across the entire historical window there are 1,423,242 packet-health samples, including eight noncapturing samples, 67 archive-error samples, 68 samples without an affirmative synchronized-clock field and 77 heartbeat gaps longer than two minutes. A missing clock field is not proof of clock drift.

Every packet sensor has a historical heartbeat gap longer than 24 hours during the November 19 to 20 reporting interruption. The longest is 105,026.722579 seconds, about 29 hours and 10 minutes. Crucially, the archive contains 6,775 research streams whose start timestamps lie inside their respective sensors' long heartbeat gaps. Reporting silence therefore cannot be treated as an equally long absence of packet capture. Buffered collection or delayed reporting is consistent with the evidence, but complete coverage is not established.

Listener receipt delay also matters. There are 2,603 accepted-connection records received more than five minutes after their event timestamps. The maximum delay is 91,325.745028 seconds, about 25 hours and 22 minutes. The two historical backfill records show why an event-time report can change after its original cutoff.

The archive reports zero partial files and zero snap-length-truncated packets. The decoder also finds zero truncated frame lengths. However, no archive file contains interface-drop statistics. Neither file integrity nor full recorded frame length proves that every packet reaching an interface was captured. Traffic outside the IPv4 TCP filter, IPv6, Tor and I2P are outside this study.

## Cross-service limits

The cross-service correlation query timed out for the new interval. Updated overlap with other honeypot services is unavailable.
