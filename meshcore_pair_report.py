#!/usr/bin/env python3
"""
meshcore_pair_report.py - repeater-paar analyse op MeshCore rx-logs.

Beantwoordt de vraag: doen twee repeaters dubbel werk, of vullen ze elkaar aan?

Het onderscheid dat ertoe doet:

  SERIEEL   A en B staan in hetzelfde pad, direct na elkaar.
            B heeft de uitzending van A opnieuw doorgegeven.
            Dat is geen verspilling - B verlengt het bereik van A.

  PARALLEL  hetzelfde pakket komt bij dezelfde ontvanger binnen via twee
            verschillende paden: een met A en zonder B, en een met B en
            zonder A. Beiden hebben hetzelfde pakket onafhankelijk de
            lucht in gedaan, naar hetzelfde ontvangstpunt.
            Dit is de dubbeling waar de klacht over gaat.

Pakketformaat volgens docs.meshcore.io/packet_format (v1):
    [header][transport_codes(4, optioneel)][path_length][path][payload]
    header  = 0bVVPPPPRR : route type bits 0-1, payload type 2-5, versie 6-7
    route   = 0 TRANSPORT_FLOOD, 1 FLOOD, 2 DIRECT, 3 TRANSPORT_DIRECT
              transport_codes alleen bij 0 en 3
    path_length: bits 0-5 hop count, bits 6-7 hash size - 1 (1/2/3 bytes)
    path   = hop_count * hash_size bytes

Pakket-identiteit: het pad groeit per hop, de payload niet. Twee kopieen van
hetzelfde pakket worden dus herkend aan (payload type, payload versie,
payload bytes). Dit is NIET de hash die de firmware zelf voor duplicate
suppression gebruikt; het is een eigen sleutel met hetzelfde effect.

Gebruik:
    python3 meshcore_pair_report.py rxlog1.jsonl rxlog2.jsonl \
        --a 5dac --a-name WKC --b 4ffc --b-name WKC-L --min-hash-size 2

    python3 meshcore_pair_report.py *.jsonl --list-hashes 40
        (eerst uitzoeken welke hash bij welke repeater hoort)

    python3 meshcore_pair_report.py *.jsonl --a 5dac --b 4ffc \
        --split 2026-09-18T20:00 --min-hash-size 2
        (voor/na een instellingswijziging, met vergelijking)

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
from datetime import datetime, timedelta, timezone

# --------------------------------------------------------------------------
# pakketstructuur
# --------------------------------------------------------------------------

ROUTE_NAMES = {
    0x00: "TRANSPORT_FLOOD",
    0x01: "FLOOD",
    0x02: "DIRECT",
    0x03: "TRANSPORT_DIRECT",
}

PAYLOAD_NAMES = {
    0x00: "REQ", 0x01: "RESPONSE", 0x02: "TXT_MSG", 0x03: "ACK",
    0x04: "ADVERT", 0x05: "GRP_TXT", 0x06: "GRP_DATA", 0x07: "ANON_REQ",
    0x08: "PATH", 0x09: "TRACE", 0x0A: "MULTIPART", 0x0B: "CONTROL",
    0x0C: "RESERVED_0C", 0x0D: "RESERVED_0D", 0x0E: "RESERVED_0E",
    0x0F: "RAW_CUSTOM",
}

FLOOD_ROUTES = (0x00, 0x01)
RAW_FIELDS = ("raw_payload", "raw", "raw_hex", "raw_data", "raw_packet",
              "payload_hex", "packet_hex", "packet", "hex", "data", "payload")
# op volgorde van voorkeur; een kandidaat telt pas als zijn waarde echt een
# datum EN tijd bevat ("time": "17:10:26" is een klokje, geen tijdstempel)
TIME_FIELDS = ("timestamp_utc", "timestamp", "received_at", "datetime",
               "rx_time", "time", "ts")


class ParseError(Exception):
    pass


def parse_packet(raw: bytes) -> dict:
    if len(raw) < 2:
        raise ParseError("te kort")

    header = raw[0]
    route = header & 0x03
    ptype = (header >> 2) & 0x0F
    pver = (header >> 6) & 0x03

    off = 1
    transport = None
    if route in (0x00, 0x03):
        if len(raw) < 6:
            raise ParseError("transport codes ontbreken")
        transport = raw[1:5]
        off = 5

    if len(raw) <= off:
        raise ParseError("path_length ontbreekt")

    plen = raw[off]
    off += 1
    hops = plen & 0x3F
    hash_size = ((plen >> 6) & 0x03) + 1
    if hash_size == 4:
        raise ParseError("gereserveerde hash size")

    need = hops * hash_size
    if len(raw) < off + need:
        raise ParseError("pad loopt voorbij pakketeinde")

    path_bytes = raw[off:off + need]
    off += need

    return {
        "route": route,
        "ptype": ptype,
        "pver": pver,
        "transport": transport,
        "hops": hops,
        "hash_size": hash_size,
        "path": [path_bytes[i * hash_size:(i + 1) * hash_size] for i in range(hops)],
        "payload": raw[off:],
        "size": len(raw),
    }


def identity(pkt: dict) -> bytes:
    h = hashlib.sha256()
    h.update(bytes([pkt["ptype"], pkt["pver"]]))
    h.update(pkt["payload"])
    return h.digest()[:12]


def path_key(pkt: dict) -> str:
    return "-".join(e.hex() for e in pkt["path"])


# --------------------------------------------------------------------------
# zendtijd
# --------------------------------------------------------------------------

def time_on_air(nbytes: int, sf: int, bw_khz: float, cr_den: int,
                preamble: int = 8, explicit_header: bool = True,
                crc: bool = True) -> float:
    """LoRa ToA in seconden (Semtech), inclusief low-data-rate-optimize regel."""
    bw = bw_khz * 1000.0
    t_sym = (2 ** sf) / bw
    de = 1 if t_sym > 0.016 else 0
    cr = cr_den - 4
    ih = 0 if explicit_header else 1
    num = 8 * nbytes - 4 * sf + 28 + (16 if crc else 0) - 20 * ih
    den = 4 * (sf - 2 * de)
    n_payload = 8 + max(math.ceil(num / den) * (cr + 4), 0)
    return (preamble + 4.25) * t_sym + n_payload * t_sym


def fmt_time(seconds: float) -> str:
    if seconds >= 3600:
        return f"{seconds / 3600:.2f} u"
    if seconds >= 60:
        return f"{seconds / 60:.1f} m"
    return f"{seconds:.1f} s"


# --------------------------------------------------------------------------
# invoer
# --------------------------------------------------------------------------

def looks_like_hex(value) -> bool:
    if not isinstance(value, str):
        return False
    cleaned = "".join(ch for ch in value if ch not in " :-_\t\n")
    if cleaned.lower().startswith("0x"):
        cleaned = cleaned[2:]
    if len(cleaned) < 4 or len(cleaned) % 2:
        return False
    return all(ch in "0123456789abcdefABCDEF" for ch in cleaned)


def find_raw(record, depth=0):
    """Zoekt het veld met de ruwe pakket-hex, ook een niveau of wat dieper.

    Nodig omdat MQTT-dumps (meshcoretomqtt, mosquitto_sub) het pakket vaak
    in een subobject zetten. Let op: het topic meshcore/packets bevat GEEN
    ruwe bytes en dus geen pad - daarvoor is meshcore/raw nodig.
    """
    if depth > 3 or not isinstance(record, dict):
        return "", None
    for name in RAW_FIELDS:
        value = record.get(name)
        if looks_like_hex(value):
            return name, value
    for key, value in record.items():
        if isinstance(value, dict):
            found, hexval = find_raw(value, depth + 1)
            if hexval:
                return f"{key}.{found}", hexval
        elif isinstance(value, str) and key not in RAW_FIELDS and looks_like_hex(value) \
                and len(value) >= 12:
            return key, value
    return "", None


def deep_get(record, dotted):
    node = record
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def pick_time_field(record: dict) -> str:
    """Eerste veld waarvan de waarde ook werkelijk als tijdstempel leest."""
    for name in TIME_FIELDS:
        if name in record and parse_timestamp(record[name]) is not None:
            return name
    return ""


def pick_field(record: dict, candidates) -> str:
    for name in candidates:
        if name in record and record[name] not in (None, ""):
            return name
    return ""


def parse_timestamp(value):
    if value is None:
        return None
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    text = str(value).strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def iter_records(path: str):
    """Leest JSON-lines of een JSON-array; beide komen in het veld voor."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        first = fh.read(1)
        while first and first.isspace():
            first = fh.read(1)
        fh.seek(0)
        if first == "[":
            try:
                data = json.load(fh)
            except json.JSONDecodeError as exc:
                raise SystemExit(f"{path}: geen geldige JSON-array ({exc})")
            for item in data:
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
                if looks_like_hex(line):          # kale hex uit mosquitto_sub
                    yield {"raw_payload": line}
                else:
                    yield None
                continue
            if isinstance(item, dict):
                yield item


def hex_to_bytes(text: str) -> bytes:
    cleaned = "".join(ch for ch in text if ch not in " :-_\t\n")
    if cleaned.lower().startswith("0x"):
        cleaned = cleaned[2:]
    if len(cleaned) % 2:
        raise ValueError("oneven aantal hex-tekens")
    return bytes.fromhex(cleaned)


# --------------------------------------------------------------------------
# matching
# --------------------------------------------------------------------------

def entry_matches(entry: bytes, target: bytes) -> bool:
    """Vergelijk over de kortste van beide. Korter = zwakker bewijs."""
    n = min(len(entry), len(target))
    return n > 0 and entry[:n] == target[:n]


def path_contains(path, target) -> bool:
    return any(entry_matches(e, target) for e in path)


def adjacency(path, a, b):
    """Levert ('a->b'|'b->a'|None): wie gaf wiens uitzending direct door."""
    for first, second in zip(path, path[1:]):
        if entry_matches(first, a) and entry_matches(second, b):
            return "a->b"
        if entry_matches(first, b) and entry_matches(second, a):
            return "b->a"
    return None


# --------------------------------------------------------------------------
# inlezen
# --------------------------------------------------------------------------

class Window:
    def __init__(self, name):
        self.name = name
        self.copies = defaultdict(lambda: defaultdict(dict))
        self.first = None
        self.last = None

    def note_time(self, when):
        if when is None:
            return
        if self.first is None or when < self.first:
            self.first = when
        if self.last is None or when > self.last:
            self.last = when

    @property
    def hours(self):
        if self.first and self.last:
            return (self.last - self.first).total_seconds() / 3600
        return 0.0


def collect(args, split_at, since, until):
    windows = {}

    def window_for(when):
        if split_at is None:
            name = "alles"
        elif when is None:
            name = "zonder tijd"
        else:
            name = "voor" if when < split_at else "na"
        if name not in windows:
            windows[name] = Window(name)
        return windows[name]

    hash_counter = Counter()
    hash_sizes = Counter()
    meta = Counter()

    for filename in args.files:
        if not os.path.exists(filename):
            raise SystemExit(f"bestand bestaat niet: {filename}")
        source = os.path.basename(filename)
        raw_field = args.field
        time_field = args.time_field

        for record in iter_records(filename):
            meta["lines"] += 1
            if record is None:
                meta["bad"] += 1
                continue
            if not raw_field:
                raw_field, _ = find_raw(record)
                if not raw_field:
                    meta["bad"] += 1
                    continue
            if not time_field:
                time_field = pick_time_field(record)

            value = deep_get(record, raw_field)
            if not value:
                meta["bad"] += 1
                continue

            when = parse_timestamp(deep_get(record, time_field)) if time_field else None
            if when is not None:
                meta["timed"] += 1
                if since and when < since:
                    meta["outside"] += 1
                    continue
                if until and when > until:
                    meta["outside"] += 1
                    continue

            try:
                raw = hex_to_bytes(value) if isinstance(value, str) else bytes(value)
                pkt = parse_packet(raw)
            except (ValueError, ParseError):
                meta["bad"] += 1
                continue

            meta["ok"] += 1
            hash_sizes[pkt["hash_size"]] += 1
            for entry in pkt["path"]:
                hash_counter[entry.hex()] += 1

            if args.flood_only and pkt["route"] not in FLOOD_ROUTES:
                continue
            if pkt["hash_size"] < args.min_hash_size:
                meta["small_hash"] += 1
                continue

            win = window_for(when)
            win.note_time(when)
            bucket = win.copies[identity(pkt)][source]
            pk = path_key(pkt)
            if pk in bucket:
                stored, count = bucket[pk]
                bucket[pk] = (stored, count + 1)
            else:
                bucket[pk] = (pkt, 1)

    return windows, hash_counter, hash_sizes, meta


# --------------------------------------------------------------------------
# analyse
# --------------------------------------------------------------------------

def analyse(window, target_a, target_b, toa):
    st = {
        "unique": 0, "copies": 0, "relay_tx": 0, "airtime": 0.0,
        "cat_counts": Counter(), "cat_airtime": defaultdict(float),
        "parallel": 0, "parallel_airtime": 0.0, "parallel_by_type": Counter(),
        "serial": Counter(), "multipath": Counter(), "truncated": 0,
        "rows": [],
    }

    for key, per_source in window.copies.items():
        st["unique"] += 1
        any_pkt = None
        paths_all = set()
        involves_a = involves_b = parallel_here = False
        pkt_airtime = 0.0
        pkt_copies = 0

        for source, bucket in per_source.items():
            paths_here = {}
            for pk, (pkt, count) in bucket.items():
                any_pkt = any_pkt or pkt
                st["copies"] += count
                pkt_copies += count
                st["relay_tx"] += pkt["hops"] * count
                air = toa(pkt["size"]) * count
                st["airtime"] += air
                pkt_airtime += air
                paths_all.add(pk)

                if pkt["hash_size"] < max(len(target_a), len(target_b)):
                    st["truncated"] += count

                has_a = path_contains(pkt["path"], target_a)
                has_b = path_contains(pkt["path"], target_b)
                involves_a |= has_a
                involves_b |= has_b
                paths_here[pk] = (has_a, has_b)

                adj = adjacency(pkt["path"], target_a, target_b)
                if adj:
                    st["serial"][adj] += count

            only_a = any(ha and not hb for ha, hb in paths_here.values())
            only_b = any(hb and not ha for ha, hb in paths_here.values())
            if only_a and only_b:
                parallel_here = True

        st["multipath"][min(len(paths_all), 6)] += 1

        if involves_a and involves_b:
            cat = "both"
        elif involves_a:
            cat = "only_a"
        elif involves_b:
            cat = "only_b"
        else:
            cat = "neither"
        st["cat_counts"][cat] += 1
        st["cat_airtime"][cat] += pkt_airtime

        if parallel_here:
            st["parallel"] += 1
            st["parallel_airtime"] += pkt_airtime
            if any_pkt:
                st["parallel_by_type"][PAYLOAD_NAMES.get(any_pkt["ptype"], "?")] += 1

        if any_pkt:
            st["rows"].append({
                "identity": key.hex(),
                "payload_type": PAYLOAD_NAMES.get(any_pkt["ptype"], "?"),
                "route": ROUTE_NAMES.get(any_pkt["route"], "?"),
                "categorie": cat,
                "parallel": int(parallel_here),
                "paden": len(paths_all),
                "kopieen": pkt_copies,
                "airtime_s": round(pkt_airtime, 4),
            })

    st["parallel_pct"] = 100.0 * st["parallel"] / st["unique"] if st["unique"] else 0.0
    return st


# --------------------------------------------------------------------------
# rapport
# --------------------------------------------------------------------------

def print_report(st, window, label_a, label_b, title=""):
    print()
    if title:
        print(f"=== {title} ===")
    if window.first and window.last:
        print(f"periode: {window.first:%Y-%m-%d %H:%M} .. {window.last:%Y-%m-%d %H:%M} "
              f"UTC ({window.hours:.1f} uur)")
    if not st["unique"]:
        print("geen pakketten in deze selectie")
        return

    print(f"unieke pakketten in selectie  : {st['unique']}")
    print(f"ontvangen kopieen             : {st['copies']}"
          f"   ({st['copies'] / st['unique']:.2f} per uniek pakket)")
    print(f"waargenomen relay-uitzendingen: {st['relay_tx']}   (som van hop counts)")
    print(f"zendtijd van ontvangen kopieen: {fmt_time(st['airtime'])}"
          f"   (dubbelgeteld over ontvangers)")
    if window.hours:
        print(f"per uur                       : {st['unique'] / window.hours:.1f} "
              f"unieke pakketten, bezetting "
              f"{st['airtime'] / (window.hours * 3600) * 100:.3f}% "
              f"(zoals hier ontvangen)")
    print()

    print("betrokkenheid per uniek pakket")
    print("-" * 62)
    for cat, text in (("both", f"beide ({label_a} en {label_b})"),
                      ("only_a", f"alleen {label_a}"),
                      ("only_b", f"alleen {label_b}"),
                      ("neither", "geen van beide")):
        count = st["cat_counts"][cat]
        pct = 100.0 * count / st["unique"]
        print(f"{text:<40}{count:>8}{pct:>7.1f}%   {fmt_time(st['cat_airtime'][cat]):>9}")
    print()

    print("aard van de betrokkenheid")
    print("-" * 62)
    w = 40
    serial_total = st["serial"]["a->b"] + st["serial"]["b->a"]
    print(f"{'serieel, ' + label_a + ' -> ' + label_b:<{w}}{st['serial']['a->b']:>8} kopieen")
    print(f"{'serieel, ' + label_b + ' -> ' + label_a:<{w}}{st['serial']['b->a']:>8} kopieen")
    print(f"{'serieel totaal':<{w}}{serial_total:>8} kopieen  (ketting: bereik verlengd)")
    print(f"{'PARALLEL gedubbeld':<{w}}{st['parallel']:>8} pakketten "
          f"({st['parallel_pct']:.1f}%)  {fmt_time(st['parallel_airtime'])}")
    print()

    if st["parallel_by_type"]:
        print("parallelle dubbeling per payload type")
        print("-" * 62)
        for name, count in st["parallel_by_type"].most_common():
            print(f"  {name:<14}{count:>8}")
        print()

    print("aantal verschillende paden per uniek pakket")
    print("-" * 62)
    for n in sorted(st["multipath"]):
        label = f"{n}" if n < 6 else "6 of meer"
        print(f"  {label:<12}{st['multipath'][n]:>10}")
    print()

    if st["truncated"]:
        print(f"LET OP: {st['truncated']} kopieen hebben kortere pad-hashes dan de")
        print("opgegeven doelhash; die zijn over de kortste lengte vergeleken.")
        print("Dat vergroot de kans op verwarring met een andere node.")
        print("Draai opnieuw met --min-hash-size 2 om die kopieen weg te laten.")
        print()


def print_comparison(before, after, win_before, win_after, label_a, label_b):
    print()
    print("=== vergelijking voor / na ===")
    print("-" * 62)
    print(f"{'':<34}{'voor':>12}{'na':>12}")

    def row(text, x, y, fmt="{:.0f}"):
        print(f"{text:<34}{fmt.format(x):>12}{fmt.format(y):>12}")

    hb, ha = win_before.hours or 1, win_after.hours or 1
    row("meetduur (uur)", win_before.hours, win_after.hours, "{:.1f}")
    row("unieke pakketten per uur", before["unique"] / hb, after["unique"] / ha, "{:.1f}")
    row("kopieen per uniek pakket",
        before["copies"] / max(before["unique"], 1),
        after["copies"] / max(after["unique"], 1), "{:.2f}")
    row("hops per kopie",
        before["relay_tx"] / max(before["copies"], 1),
        after["relay_tx"] / max(after["copies"], 1), "{:.2f}")
    row("PARALLEL gedubbeld (%)", before["parallel_pct"], after["parallel_pct"], "{:.1f}")
    row("bezetting (%)",
        before["airtime"] / (hb * 3600) * 100,
        after["airtime"] / (ha * 3600) * 100, "{:.3f}")
    print()
    delta = after["parallel_pct"] - before["parallel_pct"]
    print(f"verschil in parallelle dubbeling: {delta:+.1f} procentpunt")
    print()
    print("Let op: een enkele voor/na-vergelijking laat niet zien hoeveel het")
    print("cijfer vanzelf al schommelt. Draai dezelfde meting ook over twee")
    print("eerdere vensters van gelijke lengte zonder wijziging ertussen, en")
    print("vergelijk dat verschil met het verschil hierboven. Is het van")
    print("dezelfde orde, dan meet je ruis en geen effect.")


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def build_args():
    p = argparse.ArgumentParser(
        description="Dedup- en padanalyse voor een paar MeshCore repeaters.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("files", nargs="+", help="rx-log bestanden (JSON of JSON-lines)")
    p.add_argument("--a", help="pad-hash repeater A, hex (1-3 bytes), bv. 5dac")
    p.add_argument("--b", help="pad-hash repeater B, hex (1-3 bytes)")
    p.add_argument("--a-name", default="A", help="label repeater A")
    p.add_argument("--b-name", default="B", help="label repeater B")
    p.add_argument("--list-hashes", type=int, metavar="N", default=0,
                   help="toon de N meest voorkomende pad-hashes en stop")
    p.add_argument("--field", default="", help="veldnaam met ruwe hex (autodetectie)")
    p.add_argument("--time-field", default="", help="veldnaam met tijdstempel (autodetectie)")
    p.add_argument("--since", default="", help="alleen vanaf dit moment (ISO, UTC)")
    p.add_argument("--until", default="", help="alleen tot dit moment (ISO, UTC)")
    p.add_argument("--split", default="", metavar="TIJD",
                   help="splits op dit moment (ISO, UTC) in een venster voor en na, "
                        "met vergelijking; bv. het moment van een instellingswijziging")
    p.add_argument("--min-hash-size", type=int, choices=(1, 2, 3), default=1, metavar="N",
                   help="negeer kopieen met pad-hashes kleiner dan N bytes; "
                        "gebruik 2 als een 1-byte hash met een andere node botst")
    p.add_argument("--sf", type=int, default=7, help="spreading factor (default 7)")
    p.add_argument("--bw", type=float, default=62.5, help="bandbreedte in kHz (default 62.5)")
    p.add_argument("--cr", type=int, default=5, help="coding rate noemer 4/N (default 5)")
    p.add_argument("--preamble", type=int, default=8, help="preamble symbolen (default 8)")
    p.add_argument("--flood-only", action="store_true", default=True,
                   help="alleen flood-verkeer meetellen (default aan)")
    p.add_argument("--all-routes", dest="flood_only", action="store_false",
                   help="ook DIRECT-verkeer meetellen")
    p.add_argument("--csv", default="", help="per uniek pakket een regel naar dit bestand "
                                             "(bij --split een bestand per venster)")
    return p


def main(argv=None):
    args = build_args().parse_args(argv)

    def need_time(value, flag):
        if not value:
            return None
        parsed = parse_timestamp(value)
        if parsed is None:
            raise SystemExit(f"{flag} is geen geldige ISO-tijd (bv. 2026-09-18T20:00)")
        return parsed

    since = need_time(args.since, "--since")
    until = need_time(args.until, "--until")
    split_at = need_time(args.split, "--split")

    target_a = target_b = None
    if not args.list_hashes:
        if not args.a or not args.b:
            raise SystemExit("geef --a en --b op, of gebruik --list-hashes")
        try:
            target_a = hex_to_bytes(args.a)
            target_b = hex_to_bytes(args.b)
        except ValueError as exc:
            raise SystemExit(f"ongeldige hash: {exc}")
        if not 1 <= len(target_a) <= 3 or not 1 <= len(target_b) <= 3:
            raise SystemExit("pad-hashes zijn 1 tot 3 bytes")
        if target_a == target_b:
            raise SystemExit("A en B zijn dezelfde hash")

    windows, hash_counter, hash_sizes, meta = collect(args, split_at, since, until)

    if not meta["ok"]:
        raise SystemExit("geen leesbare pakketten gevonden - klopt --field?")

    # tijdfilters zijn zinloos zonder bruikbare tijdstempels: dan liever stoppen
    if (split_at or since or until) and not meta["timed"]:
        raise SystemExit(
            "geen bruikbare tijdstempels gevonden, dus --split/--since/--until "
            "zou stilzwijgend niets filteren.\n"
            "Geef het juiste veld op met --time-field <naam>; controleer de sleutel met:\n"
            "  head -1 <rxlog> | python3 -m json.tool")

    if args.list_hashes:
        print(f"{meta['ok']} pakketten gelezen uit {len(args.files)} bestand(en)")
        print("pad-hash groottes in gebruik: "
              + ", ".join(f"{n} byte: {c}" for n, c in sorted(hash_sizes.items())))
        print()
        print(f"{'hash':<10}{'voorkomens':>12}")
        print("-" * 22)
        for value, count in hash_counter.most_common(args.list_hashes):
            print(f"{value:<10}{count:>12}")
        print()
        print("Zoek de hash van een repeater op als de eerste byte(s) van zijn")
        print("publieke sleutel (contacten-cache). Komt dezelfde byte bij meer")
        print("dan een node voor, dan is 1-byte matching niet betrouwbaar.")
        return 0

    toa = lambda n: time_on_air(n, args.sf, args.bw, args.cr, args.preamble)
    scope = "alleen flood" if args.flood_only else "alle route types"
    if args.min_hash_size > 1:
        scope += f", pad-hash >= {args.min_hash_size} bytes"

    print()
    print(f"repeater-paar analyse   {args.a_name} ({target_a.hex()})  vs  "
          f"{args.b_name} ({target_b.hex()})")
    print(f"selectie: {scope}   SF{args.sf}  BW {args.bw} kHz  CR 4/{args.cr}  "
          f"preamble {args.preamble}")
    print(f"bestanden: {len(args.files)}   regels: {meta['lines']}   "
          f"leesbaar: {meta['ok']}   onleesbaar: {meta['bad']}   "
          f"met tijdstempel: {meta['timed']}")
    if meta["outside"]:
        print(f"buiten opgegeven periode: {meta['outside']}")
    if meta["small_hash"]:
        print(f"buiten selectie wegens korte pad-hash: {meta['small_hash']}")
    if split_at:
        print(f"splitsmoment: {split_at:%Y-%m-%d %H:%M} UTC")

    order = ["voor", "na", "zonder tijd", "alles"]
    present = [n for n in order if n in windows]
    results = {}
    for name in present:
        st = analyse(windows[name], target_a, target_b, toa)
        results[name] = st
        title = {"voor": "VOOR de wijziging", "na": "NA de wijziging",
                 "zonder tijd": "records zonder bruikbaar tijdstempel"}.get(name, "")
        print_report(st, windows[name], args.a_name, args.b_name, title)

        if args.csv and st["rows"]:
            path = args.csv
            if len(present) > 1:
                stem, ext = os.path.splitext(args.csv)
                path = f"{stem}_{name.replace(' ', '_')}{ext or '.csv'}"
            with open(path, "w", newline="", encoding="utf-8") as fh:
                writer = csv.DictWriter(fh, fieldnames=list(st["rows"][0].keys()))
                writer.writeheader()
                writer.writerows(st["rows"])
            print(f"per-pakket detail weggeschreven naar {path} ({len(st['rows'])} regels)")

    if "voor" in results and "na" in results:
        print_comparison(results["voor"], results["na"],
                         windows["voor"], windows["na"], args.a_name, args.b_name)
        if "zonder tijd" in results:
            print()
            print("LET OP: er zijn ook records zonder bruikbaar tijdstempel; die staan")
            print("hierboven apart en tellen in geen van beide vensters mee.")
    elif split_at:
        print()
        print("Een van beide vensters is leeg - ligt het splitsmoment binnen de")
        print("periode van deze logs?")

    print()
    print("lezen van dit rapport")
    print("-" * 62)
    print("* SERIEEL is geen verspilling: de een geeft de uitzending van de")
    print("  ander door en vergroot daarmee het bereik.")
    print("* PARALLEL is de dubbeling waar het om gaat: hetzelfde pakket komt")
    print("  bij dezelfde ontvanger binnen via beide repeaters afzonderlijk.")
    print("* 'alleen A' en 'alleen B' zijn het tegenbewijs: dat verkeer zou")
    print("  wegvallen als je die repeater uitzet.")
    print("* Alles hier is wat DEZE ontvangers hoorden. Uitzendingen buiten")
    print("  bereik ontbreken, dus de parallelcijfers zijn een ondergrens.")
    print("  Dedupliceert de ontvangende node voor het loggen, dan zie je")
    print("  parallelle kopieen helemaal niet.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:          # bv. doorgesluisd naar head of less
        try:
            sys.stdout.close()
        finally:
            sys.exit(0)
    except KeyboardInterrupt:
        sys.exit(130)
