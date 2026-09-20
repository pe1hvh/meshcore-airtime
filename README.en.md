# meshcore-airtime

*[Nederlandse versie](README.md) · English*

Measurement tools for airtime and flood behaviour in a
[MeshCore](https://meshcore.co.uk/) LoRa mesh. Built for one recurring argument:
*"those two repeaters are getting in each other's way, they keep repeating each
other's messages and pollute the mesh with wasted airtime."*

That claim is measurable. These tools measure it.

## Two tools, in this order

**`meshcore_toa_report.py` — where does the airtime go?**
Counts every received packet, computes its LoRa time on air, and breaks that
down by payload type, route type, hop count or last hop. This is step one: it
shows whether there is an airtime problem at all, and where it sits.

**`meshcore_pair_report.py` — are two repeaters doing duplicate work?**
Deduplicates at packet level and checks, per packet, whether two named repeaters
complement each other (serial) or do the same job twice (parallel). Step two,
for when step one raises a suspicion.

**`meshcore_req_report.py` — who generates the request traffic?**
Attributes REQ, RESPONSE, ANON_REQ and PATH to the node that sent them, showing
whether that traffic is concentrated in a few tools or spread across ordinary
users.

All three read the same source, need nothing outside the standard library, and derive
everything from `raw_payload` — the complete packet including its header —
rather than from fields the GUI derived for you.

---

## The distinction the whole argument hinges on

Repeaters forwarding each other's flood traffic is **not a fault** — it is how
flood routing works. The question is not *whether* they repeat each other's
packets, but *how*.

**Serial.** Both repeaters appear in the same path, directly after one another:
`A → B`. B picked up A's transmission and carried it further. That is not waste
but range extension — exactly what a second repeater is for.

**Parallel.** The same packet reaches the same receiver over two different
paths: one containing A but not B, another containing B but not A. Both
repeaters put that packet on the air independently, towards the same receiving
point. This is the duplication the complaint is about, and only this costs
airtime without returning anything.

Without that distinction you measure nothing. Two repeaters that cooperate
neatly show up "together in a path" just as often as two that duplicate work.

## Why you need a placebo window

A before/after measurement around a settings change means nothing until you know
how much the figure fluctuates on its own. In the measurements this tool was
written for, the parallel percentage between two consecutive two-day windows
with *no change whatsoever* in between already shifted by 6.5 percentage points.
A measured "improvement" of 3 points means nothing against that background.

So always run two windows that both precede the change first:

```bash
# establish the noise floor: two 48-hour windows, nothing changed in between
python3 meshcore_pair_report.py rxlog.jsonl \
    --a 5dac --a-name WKC --b 4ffc --b-name WKC-L --min-hash-size 2 \
    --since 2026-09-12T18:00 --until 2026-09-16T18:00 \
    --split 2026-09-14T18:00

# only then the real before/after
python3 meshcore_pair_report.py rxlog.jsonl \
    --a 5dac --a-name WKC --b 4ffc --b-name WKC-L --min-hash-size 2 \
    --since 2026-09-16T18:00 --split 2026-09-18T18:00
```

The difference from the first run is the bar the second has to clear.

## meshcore_toa_report.py — airtime per payload type

```bash
python3 meshcore_toa_report.py                      # default: ~/.meshcore-gui/archive/_dev_*_rxlog.jsonl
python3 meshcore_toa_report.py LOG --verify         # check the assumptions first
python3 meshcore_toa_report.py LOG --flood-only --hops
python3 meshcore_toa_report.py LOG --via-name WKC-L --by-last-hop
python3 meshcore_toa_report.py LOG --since 2026-09-01 --csv airtime.csv
```

Output is a table giving, per payload type, the packet count, bytes, computed
airtime, its share, and the average time per packet. Below that: the split
across the four MeshCore route types, and the channel occupancy as observed at
this receiving point.

| option | meaning |
| --- | --- |
| `--verify` | re-checks the log-format assumptions against your own data, then stops |
| `--flood-only` | TRANSPORT_FLOOD and FLOOD only: what a repeater actually retransmits |
| `--route` | restrict to one MeshCore route type |
| `--via` / `--via-name` / `--via-pos` | only traffic that passed through a given node |
| `--by-last-hop` | table per last hop instead of per payload type |
| `--hops` | hop-count distribution, including what a `flood.max` cap would save |
| `--per-day` | daily totals, useful for checking your log's coverage |

### Why `--verify` exists

The script derives everything from the raw bytes, but checks that against the
fields the GUI adds: `packet_len` against the actual length, the payload-type
bits against `packet_type_num`, the path-length byte against the hop count. If
anything diverges — new firmware, a changed GUI — it says so instead of quietly
producing wrong numbers. Run it once on your own log before using the results
anywhere.

### A trap in the log format

The `route_type` field in the meshcore-gui rxlog is **not** the MeshCore route
type. It reads `D` as soon as the packet carries a path and `F` when the path is
empty. The real route type lives in bits 0-1 of the header. Filtering on that
GUI field counts flood traffic that already has a path as "direct", and leads to
wrong conclusions about the flood/direct ratio. `--flood-only` works on the
header.

### What the first measurement produced

On a mesh in Overijssel, the Netherlands, over 192,000 packets:

* 95.5% of traffic is flood (84.1% TRANSPORT_FLOOD, 11.4% FLOOD), 4.5% DIRECT
* REQ, RESPONSE, ANON_REQ and PATH together make up almost half of all packets:
  automated chatter from tooling, not people sending messages
* ADVERT is the most expensive packet type per unit (over 450 ms) but only 5% of
  airtime — adverts are rarely the problem
* channel occupancy as received: 0.32%

That last figure puts most airtime arguments in perspective. Measure it before
you argue about it.

### Two things it underestimates

**Double counting.** Running across logs from several receivers counts a packet
heard by both twice. The output warns about this.

**DIRECT traffic.** A fixed receiving point hears every flood within range, but
only the routed traffic that happens to pass by. The DIRECT share is therefore
systematically too low. Do not draw conclusions about the flood/direct ratio
from a single receiver.

## meshcore_req_report.py — who generates the request traffic?

The first measurement showed that nearly half of all packets were REQ,
RESPONSE, ANON_REQ and PATH. The tempting conclusion is "that is automated
traffic from tooling". That is a hypothesis, not a measurement.

This script turns it into one. It reads the source and destination hash from
the payload (`[dest 1][src 1][MAC 2]` for REQ, RESPONSE, TXT_MSG and PATH; the
full sender public key for ANON_REQ) and counts per node. Node names are
harvested from the ADVERT packets in the same log, so no contact list is needed.

```bash
python3 meshcore_req_report.py rxlog.jsonl --targets
python3 meshcore_req_report.py rxlog.jsonl --top 30 --csv sources.csv
```

The answer is in the concentration table. If more than 60% of all REQ comes
from the top 3 sources, it really is a handful of polling tools. Spread across
dozens of nodes, it is ordinary use and the claim does not hold.

What it cannot do: ACK, GRP_TXT and GRP_DATA carry no sender and cannot be
attributed. And RESPONSE is under-represented at a fixed receiving point, since
routed traffic is only heard when it happens to pass by.

## meshcore_pair_report.py — serial or parallel?

First find out which path hash belongs to which repeater:

```bash
python3 meshcore_pair_report.py rxlog.jsonl --list-hashes 40
```

A node's hash is the first byte (or two, or three) of its public key. Then the
analysis:

```bash
python3 meshcore_pair_report.py rxlog.jsonl \
    --a 5dac --a-name WKC \
    --b 4ffc --b-name WKC-L \
    --min-hash-size 2 --csv pairs.csv
```

| option | meaning |
| --- | --- |
| `--a` / `--b` | path hash of both repeaters, hex, 1 to 3 bytes |
| `--min-hash-size N` | ignore copies with shorter path hashes (see below) |
| `--split TIME` | split into a before and after window, with comparison |
| `--since` / `--until` | bound the measurement period (ISO, UTC) |
| `--per-observer` | analyse each observer separately instead of pooled |
| `--all-routes` | include DIRECT traffic too (default: flood only) |
| `--sf` `--bw` `--cr` | radio parameters for the airtime calculation |
| `--csv` | write one row per unique packet |

### Why `--min-hash-size 2` is usually necessary

With one-byte path hashes there are only 254 usable IDs. In a mesh of any size,
several nodes share the same first byte of their public key, and an analysis on
one byte then counts another node's traffic as yours. In the dataset this was
written for, a repeater collided with a bot in the same region — a factor four
in the result.

The script warns when a comparison was made on a single byte. Take that warning
seriously and re-run with `--min-hash-size 2`.

## Input

Any source containing the **raw packet** works:

* meshcore-gui rx logs (`~/.meshcore-gui/archive/*_rxlog.jsonl`)
* MQTT dumps from [meshcoretomqtt](https://github.com/Andrew-a-g/meshcoretomqtt) —
  **topic `meshcore/raw`**, not `meshcore/packets`: the latter carries the packet
  hash but no path, leaving nothing to analyse
* bare hex, one packet per line (`mosquitto_sub -t meshcore/raw`)

Both JSON-lines and a JSON array are read; the field holding the hex is located
automatically, up to a few levels deep. Override with `--field` and
`--time-field`.

Packets are parsed per the
[official structure](https://docs.meshcore.io/packet_format/):
`[header][transport_codes(4, optional)][path_length][path][payload]`, with the
hop count in bits 0-5 of `path_length` and the hash size minus 1 in bits 6-7.

Copies of the same packet are recognised by payload type plus payload bytes —
the path grows per hop, the payload does not. That is not the hash the firmware
itself uses for duplicate suppression, but an equivalent key with the same
effect.

## Limits of the method

Read this before putting any number from these tools in front of anyone.

* **You measure what your receivers heard.** Transmissions out of range are
  absent. Parallel figures are therefore a lower bound, and say nothing about
  the situation around a repeater you do not receive yourself.
* **If your receiving node deduplicates before logging, you will not see
  parallel copies at all.** The figure then comes out at zero; that is not proof
  of innocence but a blind spot.
* **Check your log's coverage, not just its time span.** An archive that nominally
  spans five months but actually holds thirteen days of records yields nonsense
  hourly averages.
* **Analyse per observer, not across all rx logs at once.** Pooling two
  receivers double-counts any packet both of them heard, and "both repeaters
  involved" can arise purely because observer 1 heard it via A and observer 2
  via B — while neither saw any duplication. Use `--per-observer`. Parallel
  duplication is by definition something a single receiving point observes.
* **DIRECT traffic is undercounted** at a fixed receiving point: you hear all
  floods, but routed traffic only when it happens to pass you.

## Settings that actually matter

When the measurement does show parallel duplication, the knobs are in the
[CLI documentation](https://docs.meshcore.io/cli_commands/):

* `rxdelay` (experimental) — weakly received copies are held in a delay queue so
  strong-signal paths get priority; by the time the weak receiver processes its
  copy, the packet has often already propagated and is suppressed as a
  duplicate. It leans on an SNR difference: if two repeaters hear each other
  equally well, there is little to prioritise.
* `txdelay` — scales the random window that prevents simultaneous retransmission.
* `flood.max.unscoped` — caps unscoped flood traffic without blocking local
  messages.
* `loop.detect` — aimed at genuine loops caused by deviant firmware; it does not
  help against this kind of redundancy.

## Licence

MIT — see [LICENSE](LICENSE). Use, modify, redistribute and commercial use are
all permitted; the only condition is that the copyright line travels with it.

73 de PE1HVH
