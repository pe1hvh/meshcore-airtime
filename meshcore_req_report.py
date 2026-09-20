#!/usr/bin/env python3
"""
meshcore_req_report.py -- wie produceert het verzoekverkeer in de mesh?

Aanleiding: in een meting bleek bijna de helft van alle pakketten REQ,
RESPONSE, ANON_REQ en PATH te zijn. De verleiding is dan te zeggen "dat is
geautomatiseerd verkeer van tooling". Dat is een vermoeden, geen meting.

Dit script maakt er een meting van. Het leest de bron- en bestemmingshash uit
de payload en telt per node. Zit het verzoekverkeer geconcentreerd bij een
handvol nodes, dan is het inderdaad tooling. Is het verspreid over tientallen
nodes, dan is het gewoon gebruik en klopt het vermoeden niet.

Payloadformaat volgens docs.meshcore.io/payloads (payload versie v1):

  REQ / RESPONSE / TXT_MSG / PATH
      [dest_hash 1][src_hash 1][cipher MAC 2][ciphertext ...]
  ANON_REQ
      [dest_hash 1][afzender pubkey 32][cipher MAC 2][ciphertext ...]
  ADVERT
      [pubkey 32][timestamp 4][signature 64][appdata ...]
      appdata: [flags 1] [lat 4][lon 4] als 0x10, [feat1 2] als 0x20,
               [feat2 2] als 0x40, [naam rest] als 0x80
  ACK, GRP_TXT, GRP_DATA
      dragen geen afzender; die kunnen hier dus niet worden toegerekend.

Namen worden uit de ADVERT-pakketten in hetzelfde log gehaald, zodat je geen
contactenlijst hoeft aan te leveren.

Let op: een node-hash is EEN byte, dus 254 bruikbare waarden. Bij een mesh van
enige omvang delen meerdere nodes dezelfde hash. Het script meldt hoeveel
namen het per hash zag; staat daar meer dan 1, dan zijn de tellingen voor die
hash een optelsom van meerdere nodes.

Gebruik:
    python3 meshcore_req_report.py rxlog.jsonl
    python3 meshcore_req_report.py rxlog.jsonl --top 30 --csv bronnen.csv
    python3 meshcore_req_report.py rxlog.jsonl --since 2026-09-05 --targets

PE1HVH, september 2026. Geen externe dependencies.
"""

import argparse
import csv
import hashlib
import json
import math
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone

PAYLOAD_NAMES = {
    0x00: "REQ", 0x01: "RESPONSE", 0x02: "TXT_MSG", 0x03: "ACK",
    0x04: "ADVERT", 0x05: "GRP_TXT", 0x06: "GRP_DATA", 0x07: "ANON_REQ",
    0x08: "PATH", 0x09: "TRACE", 0x0A: "MULTIPART", 0x0B: "CONTROL",
    0x0F: "RAW_CUSTOM",
}

# payload types met [dest][src][MAC] aan het begin
ADDRESSED = {0x00, 0x01, 0x02, 0x08}
REQUEST_TYPES = {"REQ", "RESPONSE", "ANON_REQ", "PATH"}

RAW_FIELDS = ("raw_payload", "raw", "raw_hex", "payload_hex", "packet", "data")
TIME_FIELDS = ("timestamp_utc", "timestamp", "received_at", "datetime", "rx_time")


# --------------------------------------------------------------------------
# pakket en payload
# --------------------------------------------------------------------------

def parse_packet(raw: bytes):
    if len(raw) < 2:
        return None
    header = raw[0]
    route = header & 0x03
    ptype = (header >> 2) & 0x0F
    pver = (header >> 6) & 0x03
    off = 1
    if route in (0x00, 0x03):
        if len(raw) < 6:
            return None
        off = 5
    if len(raw) <= off:
        return None
    plen = raw[off]
    off += 1
    hops = plen & 0x3F
    hash_size = ((plen >> 6) & 0x03) + 1
    if hash_size == 4 or len(raw) < off + hops * hash_size:
        return None
    off += hops * hash_size
    return {"route": route, "ptype": ptype, "pver": pver, "hops": hops,
            "payload": raw[off:], "size": len(raw)}


def endpoints(pkt):
    """(bron_hash, bestemming_hash) als hex, of (None, None)."""
    p, t = pkt["payload"], pkt["ptype"]
    if pkt["pver"] != 0:
        return None, None            # v2+ heeft andere hashbreedtes
    if t in ADDRESSED and len(p) >= 2:
        return p[1:2].hex(), p[0:1].hex()
    if t == 0x07 and len(p) >= 33:   # ANON_REQ: volledige pubkey van afzender
        return p[1:2].hex(), p[0:1].hex()
    if t == 0x04 and len(p) >= 32:   # ADVERT: pubkey vooraan
        return p[0:1].hex(), None
    return None, None


def advert_name(payload: bytes):
    """Naam uit de appdata van een ADVERT, of None."""
    if len(payload) <= 100:
        return None
    flags = payload[100]
    off = 101
    if flags & 0x10:
        off += 8
    if flags & 0x20:
        off += 2
    if flags & 0x40:
        off += 2
    if not (flags & 0x80) or off >= len(payload):
        return None
    try:
        name = payload[off:].decode("utf-8", errors="replace").strip("\x00").strip()
    except Exception:
        return None
    return name or None


def identity(pkt) -> bytes:
    h = hashlib.sha256()
    h.update(bytes([pkt["ptype"], pkt["pver"]]))
    h.update(pkt["payload"])
    return h.digest()[:12]


def time_on_air(nbytes, sf, bw_khz, cr_den, preamble=8):
    bw = bw_khz * 1000.0
    t_sym = (2 ** sf) / bw
    de = 1 if t_sym > 0.016 else 0
    n = 8 + max(math.ceil((8 * nbytes - 4 * sf + 44) / (4 * (sf - 2 * de)))
                * (cr_den - 4 + 4), 0)
    return (preamble + 4.25) * t_sym + n * t_sym


def fmt_time(seconds):
    if seconds >= 3600:
        return f"{seconds / 3600:.2f} u"
    if seconds >= 60:
        return f"{seconds / 60:.1f} m"
    return f"{seconds:.1f} s"


# --------------------------------------------------------------------------
# invoer
# --------------------------------------------------------------------------

def parse_timestamp(value):
    if value is None:
        return None
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value, tz=timezone.utc)
        except Exception:
            return None
    text = str(value).strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def iter_records(path):
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        first = fh.read(1)
        while first and first.isspace():
            first = fh.read(1)
        fh.seek(0)
        if first == "[":
            for item in json.load(fh):
                if isinstance(item, dict):
                    yield item
            return
        for line in fh:
            line = line.strip().rstrip(",")
            if not line or line in ("[", "]"):
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict):
                yield item


def hex_to_bytes(text):
    cleaned = "".join(ch for ch in text if ch not in " :-_\t\n")
    if cleaned.lower().startswith("0x"):
        cleaned = cleaned[2:]
    if len(cleaned) % 2:
        raise ValueError
    return bytes.fromhex(cleaned)


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="Wie produceert het REQ/RESPONSE/ANON_REQ/PATH-verkeer?")
    ap.add_argument("files", nargs="+")
    ap.add_argument("--top", type=int, default=20, help="aantal regels per tabel")
    ap.add_argument("--targets", action="store_true",
                    help="ook een tabel per bestemming (wie wordt bevraagd)")
    ap.add_argument("--since", default="")
    ap.add_argument("--until", default="")
    ap.add_argument("--field", default="")
    ap.add_argument("--time-field", default="")
    ap.add_argument("--sf", type=int, default=7)
    ap.add_argument("--bw", type=float, default=62.5)
    ap.add_argument("--cr", type=int, default=5)
    ap.add_argument("--preamble", type=int, default=8)
    ap.add_argument("--csv", default="")
    args = ap.parse_args()

    since = parse_timestamp(args.since) if args.since else None
    until = parse_timestamp(args.until) if args.until else None

    seen = set()
    by_src = defaultdict(Counter)        # hash -> payload type -> aantal
    by_dst = defaultdict(Counter)
    airtime_src = defaultdict(float)
    names = defaultdict(Counter)         # hash -> naam -> aantal adverts
    type_totals = Counter()
    total_air = 0.0
    n_ok = n_lines = n_bad = 0
    first = last = None

    for filename in args.files:
        if not os.path.exists(filename):
            raise SystemExit(f"bestand bestaat niet: {filename}")
        raw_field, time_field = args.field, args.time_field
        for record in iter_records(filename):
            n_lines += 1
            if not raw_field:
                for name in RAW_FIELDS:
                    if record.get(name):
                        raw_field = name
                        break
            if not time_field:
                for name in TIME_FIELDS:
                    if parse_timestamp(record.get(name)) is not None:
                        time_field = name
                        break
            value = record.get(raw_field) if raw_field else None
            if not value:
                n_bad += 1
                continue

            when = parse_timestamp(record.get(time_field)) if time_field else None
            if when is not None:
                if since and when < since:
                    continue
                if until and when > until:
                    continue
                first = when if first is None or when < first else first
                last = when if last is None or when > last else last

            try:
                pkt = parse_packet(hex_to_bytes(value))
            except ValueError:
                pkt = None
            if pkt is None:
                n_bad += 1
                continue
            n_ok += 1

            key = identity(pkt)
            if key in seen:              # kopie van hetzelfde pakket
                continue
            seen.add(key)

            tname = PAYLOAD_NAMES.get(pkt["ptype"], "?")
            air = time_on_air(pkt["size"], args.sf, args.bw, args.cr, args.preamble)
            type_totals[tname] += 1
            total_air += air

            if pkt["ptype"] == 0x04:
                nm = advert_name(pkt["payload"])
                if nm:
                    names[pkt["payload"][0:1].hex()][nm] += 1

            src, dst = endpoints(pkt)
            if src:
                by_src[src][tname] += 1
                airtime_src[src] += air
            if dst:
                by_dst[dst][tname] += 1

    if not n_ok:
        raise SystemExit("geen leesbare pakketten gevonden - klopt --field?")

    def label(h):
        if h in names and names[h]:
            best = names[h].most_common(1)[0][0]
            extra = f" (+{len(names[h]) - 1})" if len(names[h]) > 1 else ""
            return f"{h}  {best[:26]}{extra}"
        return f"{h}  -"

    req_total = sum(c["REQ"] for c in by_src.values())
    verzoek_total = sum(type_totals[t] for t in REQUEST_TYPES)
    uniq_total = sum(type_totals.values())

    print()
    print("verzoekverkeer per node -- wie produceert het?")
    print(f"selectie: SF{args.sf}  BW {args.bw} kHz  CR 4/{args.cr}")
    if first and last:
        hours = (last - first).total_seconds() / 3600
        print(f"periode: {first:%Y-%m-%d %H:%M} .. {last:%Y-%m-%d %H:%M} UTC "
              f"({hours:.1f} uur)")
    print(f"regels: {n_lines}   leesbaar: {n_ok}   onleesbaar: {n_bad}   "
          f"unieke pakketten: {uniq_total}")
    print()
    print(f"REQ + RESPONSE + ANON_REQ + PATH: {verzoek_total} van {uniq_total} "
          f"unieke pakketten ({100.0 * verzoek_total / uniq_total:.1f}%)")
    print()

    ranked = sorted(by_src.items(),
                    key=lambda kv: sum(kv[1][t] for t in REQUEST_TYPES),
                    reverse=True)

    print(f"{'bron':<32}{'REQ':>8}{'RESP':>8}{'ANON':>8}{'PATH':>8}{'TXT':>8}"
          f"{'zendtijd':>11}")
    print("-" * 83)
    for h, counts in ranked[:args.top]:
        print(f"{label(h):<32}{counts['REQ']:>8}{counts['RESPONSE']:>8}"
              f"{counts['ANON_REQ']:>8}{counts['PATH']:>8}{counts['TXT_MSG']:>8}"
              f"{fmt_time(airtime_src[h]):>11}")
    print("-" * 83)
    print(f"{'nodes met verzoekverkeer':<32}{len(ranked):>8}")
    print()

    # concentratie: het eigenlijke antwoord op de vraag
    req_ranked = sorted((c["REQ"] for c in by_src.values()), reverse=True)
    print("concentratie van het REQ-verkeer")
    print("-" * 50)
    if req_total:
        for n in (1, 3, 5, 10):
            share = 100.0 * sum(req_ranked[:n]) / req_total
            print(f"  top {n:<3} van {len(req_ranked):<4} bronnen: {share:5.1f}% "
                  f"van alle REQ")
        print()
        print("  Boven de 60% voor de top 3: geconcentreerd, dus vrijwel zeker")
        print("  een paar pollende tools. Onder de 30%: verspreid gebruik, en")
        print("  dan is 'het komt van tooling' niet houdbaar.")
    else:
        print("  geen REQ-verkeer met leesbare bronhash in deze selectie")
    print()

    if args.targets:
        print("meest bevraagde bestemmingen")
        print("-" * 60)
        print(f"{'bestemming':<32}{'REQ':>8}{'ANON':>8}{'RESP':>8}")
        for h, counts in sorted(by_dst.items(),
                                key=lambda kv: kv[1]["REQ"] + kv[1]["ANON_REQ"],
                                reverse=True)[:args.top]:
            print(f"{label(h):<32}{counts['REQ']:>8}{counts['ANON_REQ']:>8}"
                  f"{counts['RESPONSE']:>8}")
        print()

    collisions = {h: len(v) for h, v in names.items() if len(v) > 1}
    if collisions:
        print("LET OP: deze node-hashes zijn van meer dan een node "
              "(zelfde eerste byte):")
        for h, n in sorted(collisions.items(), key=lambda kv: -kv[1])[:10]:
            print(f"  {h}: {n} namen -- {', '.join(list(names[h])[:4])}")
        print("Tellingen voor die hashes zijn een optelsom.")
        print()

    print("lezen van dit rapport")
    print("-" * 60)
    print("* Geteld zijn unieke pakketten, niet ontvangen kopieen.")
    print("* ACK, GRP_TXT en GRP_DATA dragen geen afzender en staan er dus")
    print("  niet in; die zijn niet aan een node toe te rekenen.")
    print("* RESPONSE hoort bij de bevraagde node, niet bij de vrager. Wil je")
    print("  weten of verzoeken beantwoord worden, vergelijk dan REQ van een")
    print("  node met RESPONSE naar diezelfde node (--targets).")
    print("* Een vast ontvangstpunt hoort floods compleet maar gericht verkeer")
    print("  maar gedeeltelijk; RESPONSE is daardoor ondervertegenwoordigd.")

    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["bron_hash", "naam", "REQ", "RESPONSE", "ANON_REQ",
                        "PATH", "TXT_MSG", "airtime_s"])
            for h, counts in ranked:
                nm = names[h].most_common(1)[0][0] if names.get(h) else ""
                w.writerow([h, nm, counts["REQ"], counts["RESPONSE"],
                            counts["ANON_REQ"], counts["PATH"],
                            counts["TXT_MSG"], round(airtime_src[h], 3)])
        print()
        print(f"per bron weggeschreven naar {args.csv}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:
        sys.exit(0)
    except KeyboardInterrupt:
        sys.exit(130)
