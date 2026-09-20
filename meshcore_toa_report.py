#!/usr/bin/env python3
"""
meshcore_toa_report.py -- zendtijd per payload type, uit de meshcore-gui rxlog.

Alles wordt uit raw_payload afgeleid: dat is het volledige pakket inclusief
header, en daarmee de enige bron in het log die niet van een interpretatie van
de gui afhangt. De losse velden worden alleen gebruikt als raw_payload ontbreekt.

Geverifieerd tegen 21.000 records van _dev_ttyUSB1_rxlog.jsonl (sept 2026):

  packet_len        == len(raw_payload), zonder uitzondering
  header bit 2-5    == packet_type_num, zonder uitzondering
  header bit 0-1    == MeshCore route type (0 TRANSPORT_FLOOD, 1 FLOOD,
                       2 DIRECT, 3 TRANSPORT_DIRECT); bij 0 en 3 volgen
                       4 transport-bytes na de header
  header bit 6-7    == payload version, overal 0
  padlengtebyte     == (hashbreedte_in_bytes - 1) << 6 | aantal hops
  route_type veld   == 'D' als er een pad is, 'F' als het pad leeg is.
                       Dit is NIET het MeshCore route type. Gebruik --flood-only,
                       dat op de header werkt.

Draai --verify om die aannames op je eigen log na te rekenen. Wijkt er iets af
(nieuwe firmware, gewijzigde gui), dan meldt hij dat in plaats van stil door te
tellen met verkeerde cijfers.

Gebruik:
    python3 meshcore_toa_report.py LOG --verify
    python3 meshcore_toa_report.py LOG --sf 7 --bw 62.5 --cr 5
    python3 meshcore_toa_report.py LOG --flood-only --hops
    python3 meshcore_toa_report.py LOG --via-name WKC-L --by-last-hop
    python3 meshcore_toa_report.py LOG --since 2026-09-01 --csv airtime.csv

73 de PE1HVH
"""

from __future__ import annotations

import argparse
import csv
import glob
import json
import math
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone

PAYLOAD_TYPES = {
    0: "REQ",
    1: "RESPONSE",
    2: "TXT_MSG",
    3: "ACK",
    4: "ADVERT",
    5: "GRP_TXT",
    6: "GRP_DATA",
    7: "ANON_REQ",
    8: "PATH",
    9: "TRACE",
    10: "MULTIPART",
    11: "CONTROL",          # naam uit de gui; niet tegen de firmwarebron gecheckt
    15: "RAW_CUSTOM",
}

ROUTE_TYPES = {
    0: "TRANSPORT_FLOOD",
    1: "FLOOD",
    2: "DIRECT",
    3: "TRANSPORT_DIRECT",
}

FLOOD_ROUTES = {0, 1}          # wat een repeater herhaalt
TRANSPORT_ROUTES = {0, 3}      # deze dragen 4 transport-bytes na de header

DEFAULT_GLOB = os.path.expanduser("~/.meshcore-gui/archive/_dev_*_rxlog.jsonl")


# ---------------------------------------------------------------------------
# Time on air (Semtech LoRa, expliciete header, CRC aan)
# ---------------------------------------------------------------------------

def time_on_air(packet_len: int, sf: int, bw_khz: float, cr_denom: int,
                preamble: int = 8, explicit_header: bool = True,
                crc_on: bool = True, ldro: bool | None = None) -> float:
    bw_hz = bw_khz * 1000.0
    t_sym = (2.0 ** sf) / bw_hz
    if ldro is None:
        ldro = t_sym >= 0.01638          # verplicht zodra een symbool >= 16,38 ms duurt
    de = 1 if ldro else 0
    ih = 0 if explicit_header else 1
    crc = 1 if crc_on else 0
    cr = cr_denom - 4                    # 5..8 -> 1..4
    t_preamble = (preamble + 4.25) * t_sym
    num = 8 * packet_len - 4 * sf + 28 + 16 * crc - 20 * ih
    den = 4 * (sf - 2 * de)
    n_payload = 8 + max(math.ceil(num / den) * (cr + 4), 0)
    return t_preamble + n_payload * t_sym


# ---------------------------------------------------------------------------
# Pakket ontleden
# ---------------------------------------------------------------------------

class Packet:
    __slots__ = ("ptype", "route", "version", "hash_width", "hops", "path",
                 "length", "dt", "names", "raw_ok", "source")

    def __init__(self):
        self.ptype = -1
        self.route = -1
        self.version = 0
        self.hash_width = 0
        self.hops = 0
        self.path: list[str] = []
        self.length = 0
        self.dt: datetime | None = None
        self.names: list[str] = []
        self.raw_ok = False
        self.source = "raw"


def parse_timestamp(value) -> datetime | None:
    if isinstance(value, (int, float)):
        seconds = value / 1000.0 if value > 1e11 else float(value)
        try:
            return datetime.fromtimestamp(seconds, tz=timezone.utc)
        except (OSError, OverflowError, ValueError):
            return None
    if isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError:
            return None
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    return None


def parse_record(record: dict) -> Packet | None:
    """Ontleedt een rxlog-record. Bij voorkeur uit raw_payload."""
    pkt = Packet()
    pkt.dt = parse_timestamp(record.get("timestamp_utc") or record.get("timestamp")
                             or record.get("time"))

    names = record.get("path_names")
    if isinstance(names, list):
        pkt.names = [str(n) for n in names]

    raw_hex = record.get("raw_payload") or ""
    if isinstance(raw_hex, str) and len(raw_hex) >= 2:
        try:
            raw = bytes.fromhex(raw_hex)
        except ValueError:
            raw = b""
        if raw:
            header = raw[0]
            pkt.ptype = (header >> 2) & 0x0F
            pkt.route = header & 0x03
            pkt.version = (header >> 6) & 0x03
            pkt.length = len(raw)
            pkt.raw_ok = True

            offset = 1 + (4 if pkt.route in TRANSPORT_ROUTES else 0)
            if len(raw) > offset:
                path_byte = raw[offset]
                pkt.hash_width = ((path_byte >> 6) & 0x03) + 1
                pkt.hops = path_byte & 0x3F
                start = offset + 1
                end = start + pkt.hops * pkt.hash_width
                if end <= len(raw):
                    pkt.path = [raw[i:i + pkt.hash_width].hex()
                                for i in range(start, end, pkt.hash_width)]
                else:
                    pkt.hops = 0            # onvolledig pakket: pad niet vertrouwen
            return pkt

    # Terugval: geen raw_payload in dit record.
    pkt.source = "velden"
    try:
        pkt.ptype = int(record["packet_type_num"])
        pkt.length = int(record["packet_len"])
    except (KeyError, TypeError, ValueError):
        return None
    hashes = record.get("path_hashes")
    if isinstance(hashes, list):
        pkt.path = [str(h).lower() for h in hashes]
        pkt.hops = len(pkt.path)
        if pkt.path:
            pkt.hash_width = len(pkt.path[0]) // 2
    return pkt


def iter_records(paths):
    for path in paths:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        yield None
                        continue
                    if isinstance(record, dict):
                        yield record
        except OSError as exc:
            print(f"kan {path} niet lezen: {exc}", file=sys.stderr)


# ---------------------------------------------------------------------------
# --verify
# ---------------------------------------------------------------------------

def verify(paths) -> int:
    n = bad_len = bad_type = bad_ver = bad_path = no_raw = 0
    route_vs_field = Counter()
    widths = Counter()
    mixed_width = 0

    for record in iter_records(paths):
        if record is None:
            continue
        n += 1
        raw_hex = record.get("raw_payload") or ""
        if not raw_hex:
            no_raw += 1
            continue
        pkt = parse_record(record)
        if pkt is None or not pkt.raw_ok:
            no_raw += 1
            continue

        if "packet_len" in record and pkt.length != record["packet_len"]:
            bad_len += 1
        if "packet_type_num" in record and pkt.ptype != record["packet_type_num"]:
            bad_type += 1
        if pkt.version != 0:
            bad_ver += 1

        gui_path = record.get("path_hashes")
        if isinstance(gui_path, list):
            if [h.lower() for h in gui_path] != pkt.path:
                bad_path += 1
            if len({len(h) for h in gui_path}) > 1:
                mixed_width += 1
        widths[pkt.hash_width] += 1

        if "route_type" in record:
            route_vs_field[(record["route_type"], bool(pkt.path))] += 1

    def line(label, count):
        verdict = "OK" if count == 0 else f"LET OP: {count} afwijkingen"
        print(f"  {label:<52}{verdict}")

    print(f"gecontroleerd: {n} records ({no_raw} zonder bruikbare raw_payload)\n")
    line("packet_len == lengte van raw_payload", bad_len)
    line("header bit 2-5 == packet_type_num", bad_type)
    line("payload version (header bit 6-7) == 0", bad_ver)
    line("pad uit de header == path_hashes van de gui", bad_path)
    line("hashbreedte uniform binnen een pakket", mixed_width)

    print(f"\n  hashbreedte in bytes: "
          f"{', '.join(f'{w}: {c}' for w, c in sorted(widths.items()))}")

    print("\n  gui-veld route_type tegenover 'heeft een pad':")
    for (value, has_path), count in sorted(route_vs_field.items()):
        print(f"    route_type {value!r:<10} pad aanwezig: {str(has_path):<6}{count}")
    print("    'D' hoort samen te vallen met een pad en 'F' met een leeg pad.")
    print("    Dat veld zegt dus niets over flood of direct; --flood-only")
    print("    gebruikt daarom de header.")
    return 0


# ---------------------------------------------------------------------------
# Rapport
# ---------------------------------------------------------------------------

def human_seconds(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:8.1f} s"
    if seconds < 3600:
        return f"{seconds / 60:8.1f} m"
    return f"{seconds / 3600:8.2f} u"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="*", help=f"rxlog-bestanden (default: {DEFAULT_GLOB})")
    ap.add_argument("--sf", type=int, default=7)
    ap.add_argument("--bw", type=float, default=62.5, help="bandbreedte in kHz")
    ap.add_argument("--cr", type=int, default=5, choices=(5, 6, 7, 8),
                    help="coding rate als noemer: 5 = 4/5")
    ap.add_argument("--preamble", type=int, default=8)
    ap.add_argument("--since")
    ap.add_argument("--until")
    ap.add_argument("--verify", action="store_true",
                    help="reken de aannames over het logformaat na en stop")
    ap.add_argument("--flood-only", action="store_true",
                    help="alleen TRANSPORT_FLOOD en FLOOD (wat een repeater herhaalt)")
    ap.add_argument("--route", choices=sorted(ROUTE_TYPES.values()),
                    help="alleen dit MeshCore route type")
    ap.add_argument("--via", help="alleen pakketten waarvan de laatste padhash hiermee "
                                  "begint (hex, bv. 4f of 4ffc18)")
    ap.add_argument("--via-pos", choices=("last", "first", "any"), default="last")
    ap.add_argument("--via-name", help="alleen pakketten waarvan de padnaam op die "
                                       "positie deze tekst bevat -- betrouwbaarder dan "
                                       "--via, want namen botsen niet")
    ap.add_argument("--by-last-hop", action="store_true",
                    help="tabel per laatste hop in plaats van per payload type")
    ap.add_argument("--hops", action="store_true",
                    help="verdeling naar hopcount, met wat een flood.max-cap scheelt")
    ap.add_argument("--per-day", action="store_true")
    ap.add_argument("--csv")
    args = ap.parse_args()

    paths = args.paths or sorted(glob.glob(DEFAULT_GLOB))
    if not paths:
        print(f"geen rxlog gevonden ({DEFAULT_GLOB})", file=sys.stderr)
        return 1
    if len(paths) > 1:
        print(f"let op: {len(paths)} bestanden; twee ontvangers horen deels dezelfde "
              f"pakketten, dus zendtijd wordt dan dubbel geteld.\n", file=sys.stderr)

    if args.verify:
        return verify(paths)

    since = datetime.fromisoformat(args.since).replace(tzinfo=timezone.utc) if args.since else None
    until = datetime.fromisoformat(args.until).replace(tzinfo=timezone.utc) if args.until else None
    want_route = None
    if args.route:
        want_route = {code for code, name in ROUTE_TYPES.items() if name == args.route}

    via = args.via.strip().lower() if args.via else None
    via_name = args.via_name.lower() if args.via_name else None

    stats = defaultdict(lambda: {"count": 0, "bytes": 0, "toa": 0.0})
    route_mix = Counter()
    hop_toa = defaultdict(float)
    hop_count = Counter()
    matched_hop = Counter()
    per_day = defaultdict(lambda: defaultdict(float))
    unparsed = no_path = total_lines = fallback = 0
    first_dt = last_dt = None
    total_toa = 0.0

    for record in iter_records(paths):
        total_lines += 1
        if record is None:
            unparsed += 1
            continue
        pkt = parse_record(record)
        if pkt is None:
            unparsed += 1
            continue
        if pkt.source == "velden":
            fallback += 1

        if since and (pkt.dt is None or pkt.dt < since):
            continue
        if until and (pkt.dt is None or pkt.dt > until):
            continue
        if args.flood_only and pkt.route not in FLOOD_ROUTES:
            continue
        if want_route is not None and pkt.route not in want_route:
            continue

        if via or via_name:
            if not pkt.path:
                no_path += 1
                continue
            if args.via_pos == "last":
                idx = [len(pkt.path) - 1]
            elif args.via_pos == "first":
                idx = [0]
            else:
                idx = list(range(len(pkt.path)))

            hit = None
            if via:
                for i in idx:
                    if pkt.path[i].startswith(via):
                        hit = i
                        break
            if via_name:
                for i in idx:
                    if i < len(pkt.names) and via_name in pkt.names[i].lower():
                        hit = i
                        break
            if hit is None:
                continue
            label = pkt.names[hit] if hit < len(pkt.names) else ""
            matched_hop[(pkt.path[hit], label)] += 1

        if pkt.dt:
            first_dt = pkt.dt if first_dt is None or pkt.dt < first_dt else first_dt
            last_dt = pkt.dt if last_dt is None or pkt.dt > last_dt else last_dt

        toa = time_on_air(pkt.length, args.sf, args.bw, args.cr, preamble=args.preamble)
        total_toa += toa

        if args.by_last_hop:
            if pkt.path:
                name = pkt.names[-1] if pkt.names else pkt.path[-1]
                key = f"{pkt.path[-1]}  {name}"[:38]
            else:
                key = "(geen pad -- rechtstreeks gehoord)"
        else:
            key = PAYLOAD_TYPES.get(pkt.ptype, f"ONBEKEND_{pkt.ptype}")

        bucket = stats[key]
        bucket["count"] += 1
        bucket["bytes"] += pkt.length
        bucket["toa"] += toa
        route_mix[ROUTE_TYPES.get(pkt.route, f"?{pkt.route}")] += 1
        hop_toa[pkt.hops] += toa
        hop_count[pkt.hops] += 1
        if args.per_day and pkt.dt:
            per_day[pkt.dt.date()][key] += toa

    if not stats:
        print("niets te tellen -- draai --verify om het logformaat na te gaan",
              file=sys.stderr)
        return 1

    total_count = sum(b["count"] for b in stats.values())

    print(f"SF{args.sf}  BW {args.bw} kHz  CR 4/{args.cr}  preamble {args.preamble}")
    if first_dt and last_dt:
        span_h = (last_dt - first_dt).total_seconds() / 3600
        print(f"periode: {first_dt:%Y-%m-%d %H:%M} .. {last_dt:%Y-%m-%d %H:%M} UTC "
              f"({span_h:.1f} uur)")
    print(f"{total_count} pakketten van {total_lines} regels "
          f"({unparsed} onleesbaar, {fallback} zonder raw_payload)")
    if args.flood_only:
        print("alleen TRANSPORT_FLOOD en FLOOD")
    if args.route:
        print(f"alleen route type {args.route}")
    if via:
        print(f"alleen padhash beginnend met {via!r} op positie '{args.via_pos}'"
              f"  ({no_path} zonder pad overgeslagen)")
    if via_name:
        print(f"alleen padnaam met {args.via_name!r} op positie '{args.via_pos}'"
              f"  ({no_path} zonder pad overgeslagen)")
    print()

    label = "laatste hop" if args.by_last_hop else "payload type"
    head = (f"{label:<40}{'pakketten':>10}{'%pkt':>7}{'bytes':>11}"
            f"{'airtime':>12}{'%airtime':>10}{'gem. ms':>9}")
    print(head)
    print("-" * len(head))
    rows = sorted(stats.items(), key=lambda kv: kv[1]["toa"], reverse=True)
    for name, b in rows:
        print(f"{name:<40}{b['count']:>10}{100 * b['count'] / total_count:>6.1f}%"
              f"{b['bytes']:>11}{human_seconds(b['toa']):>12}"
              f"{100 * b['toa'] / total_toa:>9.1f}%"
              f"{1000 * b['toa'] / b['count']:>9.1f}")
    print("-" * len(head))
    print(f"{'totaal':<40}{total_count:>10}{'':>7}"
          f"{sum(b['bytes'] for b in stats.values()):>11}{human_seconds(total_toa):>12}")

    print("\nMeshCore route type in deze selectie:")
    for name, count in route_mix.most_common():
        print(f"    {name:<20}{count:>9}{100 * count / total_count:>7.1f}%")

    if first_dt and last_dt and last_dt > first_dt:
        span = (last_dt - first_dt).total_seconds()
        print(f"\nbezetting zoals hier ONTVANGEN: {100 * total_toa / span:.2f}% van de tijd.")
        print("Dit is RX. Je eigen duty cycle staat in de repeater-stats (airtime/uptime).")

    if args.hops:
        print("\nverdeling naar hopcount")
        print(f"{'hops':>6}{'pakketten':>11}{'airtime':>12}{'%airtime':>10}"
              f"{'cumulatief':>12}")
        cum = 0.0
        for h in sorted(hop_toa):
            cum += hop_toa[h]
            print(f"{h:>6}{hop_count[h]:>11}{human_seconds(hop_toa[h]):>12}"
                  f"{100 * hop_toa[h] / total_toa:>9.1f}%{100 * cum / total_toa:>11.1f}%")
        print("\nWat een flood.max-cap zou wegsnijden (alles boven de grens):")
        for cap in (2, 3, 4, 5, 6, 8, 10):
            cut = sum(t for h, t in hop_toa.items() if h > cap)
            if cut:
                print(f"    cap {cap:>2}: {100 * cut / total_toa:>5.1f}% van de zendtijd"
                      f"  ({sum(c for h, c in hop_count.items() if h > cap)} pakketten)")

    if matched_hop:
        print("\nwie er op de gefilterde positie stond (controle op hash-collisies):")
        for (h, name), count in matched_hop.most_common(10):
            print(f"    {count:>8}  {h:<8}{name}")
        print("Meerdere namen bij dezelfde hash betekent een collisie; filter dan")
        print("op --via-name of geef een langere hash mee.")
        print("\nIJKING: zet het pakketaantal naast sent_flood + sent_direct uit de")
        print("repeater-stats over dezelfde periode. Het verschil is het deel van")
        print("zijn zendingen dat je ontvanger niet opvangt.")

    if args.per_day:
        print("\nairtime per dag (seconden)")
        names = [n for n, _ in rows][:8]
        print(f"{'datum':<12}" + "".join(f"{n[:11]:>12}" for n in names))
        for day in sorted(per_day):
            print(f"{str(day):<12}" + "".join(f"{per_day[day][n]:>12.1f}" for n in names))

    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow([label, "packets", "bytes", "toa_seconds", "pct_airtime",
                        "avg_ms", "sf", "bw_khz", "cr", "period_start", "period_end"])
            for name, b in rows:
                w.writerow([name, b["count"], b["bytes"], f"{b['toa']:.3f}",
                            f"{100 * b['toa'] / total_toa:.2f}",
                            f"{1000 * b['toa'] / b['count']:.2f}",
                            args.sf, args.bw, args.cr,
                            first_dt.isoformat() if first_dt else "",
                            last_dt.isoformat() if last_dt else ""])
        print(f"\nCSV geschreven naar {args.csv}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
