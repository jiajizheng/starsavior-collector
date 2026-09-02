#!/usr/bin/env python3
"""Passive StarSavior PvP PCAPNG decoder (live schema snapshot, Sep 2026).

Reads a Wireshark/TShark/Npcap .pcapng, reassembles TCP, parses StarSavior
frames, applies the game's XOR/LZ4 body transform, deserializes selected packet
classes using a bundled schema snapshot, and writes normalized match JSON.

No process injection, memory reading, traffic modification, or TLS interception.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import struct
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

try:
    import lz4.frame
except ImportError:
    print("Missing dependency: lz4. Run: py -m pip install lz4", file=sys.stderr)
    raise SystemExit(2)

START_MAGIC = b"\xDD\xCC\xBB\xAA"
END_MAGIC = b"\x44\x33\x22\x11"
MASKS = (
    0xC4A975489AA72956,
    0xD7C1A29E30FAE47B,
    0xDCD6D3F2CCC0DEF9,
    0x3063872F85428EFC,
)

# Packets used by the first normalized match model.
PID_VERIFY_REQ = 1687
PID_ARENA_MATCH_NOT = 1691
PID_PVP_START_BATTLE_NOT = 1609
PID_BATTLE_NEXT_TURN_NOT = 608
PID_BATTLE_END_NOT = 612
PID_RANK_HISTORY_ACK = 1681


class DecodeError(Exception):
    pass


# ---------------------------------------------------------------------------
# PCAPNG + TCP
# ---------------------------------------------------------------------------

def iter_pcapng_packets(path: Path):
    data = path.read_bytes()
    off = 0
    endian = "<"
    interfaces: Dict[int, Dict[str, int]] = {}

    while off + 12 <= len(data):
        raw_type = data[off : off + 4]
        if raw_type == b"\x0A\x0D\x0D\x0A":
            bom = data[off + 8 : off + 12]
            if bom == b"\x4D\x3C\x2B\x1A":
                endian = "<"
            elif bom == b"\x1A\x2B\x3C\x4D":
                endian = ">"
            else:
                raise DecodeError(f"Unsupported PCAPNG byte-order magic at {off}")
            block_type = 0x0A0D0D0A
            block_len = struct.unpack_from(endian + "I", data, off + 4)[0]
        else:
            block_type, block_len = struct.unpack_from(endian + "II", data, off)

        if block_len < 12 or off + block_len > len(data):
            raise DecodeError(f"Invalid PCAPNG block at {off}: len={block_len}")

        body = data[off + 8 : off + block_len - 4]

        if block_type == 1 and len(body) >= 8:  # Interface Description Block
            linktype, _reserved, _snaplen = struct.unpack_from(endian + "HHI", body, 0)
            interfaces[len(interfaces)] = {"linktype": linktype}

        elif block_type == 6 and len(body) >= 20:  # Enhanced Packet Block
            iid, ts_hi, ts_lo, cap_len, _pkt_len = struct.unpack_from(endian + "IIIII", body, 0)
            packet = body[20 : 20 + cap_len]
            yield iid, (ts_hi << 32) | ts_lo, packet, interfaces.get(iid, {})

        off += block_len


def parse_tcp(packet: bytes, linktype: int):
    # Npcap Ethernet captures are linktype 1. Raw IPv4 is also accepted.
    if linktype == 1:
        if len(packet) < 14:
            return None
        ethertype = struct.unpack_from("!H", packet, 12)[0]
        pos = 14
        if ethertype in (0x8100, 0x88A8):
            if len(packet) < 18:
                return None
            ethertype = struct.unpack_from("!H", packet, 16)[0]
            pos = 18
        if ethertype != 0x0800:
            return None
        ip = packet[pos:]
    elif linktype == 101:  # raw IP
        ip = packet
    else:
        return None

    if len(ip) < 20 or (ip[0] >> 4) != 4 or ip[9] != 6:
        return None
    ihl = (ip[0] & 0x0F) * 4
    total_len = struct.unpack_from("!H", ip, 2)[0]
    if ihl < 20 or len(ip) < ihl:
        return None
    total_len = min(total_len, len(ip))
    src = str(ipaddress.ip_address(ip[12:16]))
    dst = str(ipaddress.ip_address(ip[16:20]))
    tcp = ip[ihl:total_len]
    if len(tcp) < 20:
        return None
    sport, dport, seq, ack = struct.unpack_from("!HHII", tcp, 0)
    doff = (tcp[12] >> 4) * 4
    if doff < 20 or doff > len(tcp):
        return None
    return src, dst, sport, dport, seq, ack, tcp[13], tcp[doff:]


def reassemble_tcp(path: Path):
    streams: Dict[Tuple[str, str, int, int], List[Tuple[int, bytes, int]]] = defaultdict(list)
    for iid, ts, packet, meta in iter_pcapng_packets(path):
        parsed = parse_tcp(packet, meta.get("linktype", -1))
        if not parsed:
            continue
        src, dst, sport, dport, seq, _ack, _flags, payload = parsed
        if payload:
            streams[(src, dst, sport, dport)].append((seq, payload, ts))

    result = {}
    for key, segs in streams.items():
        segs.sort(key=lambda x: x[0])
        current = segs[0][0]
        buf = bytearray()
        gaps = []
        for seq, payload, _ts in segs:
            if seq > current:
                gaps.append((current, seq))
                # Keep offsets stable; a gap means frames crossing it may fail validation.
                buf.extend(b"\x00" * (seq - current))
                current = seq
            if seq + len(payload) <= current:
                continue  # duplicate/retransmission entirely covered
            trim = max(0, current - seq)
            buf.extend(payload[trim:])
            current = seq + len(payload)
        result[key] = {"data": bytes(buf), "gaps": gaps, "segments": len(segs)}
    return result


# ---------------------------------------------------------------------------
# StarSavior framing / transport body transform
# ---------------------------------------------------------------------------

def read_varuint(buf: bytes, pos: int, max_bits: int = 64):
    value = 0
    shift = 0
    while shift < max_bits:
        if pos >= len(buf):
            raise DecodeError("Truncated varint")
        b = buf[pos]
        pos += 1
        value |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            return value, pos
        shift += 7
    raise DecodeError("Malformed varint")


def zigzag(value: int) -> int:
    return (value >> 1) ^ -(value & 1)


def iter_star_frames(stream: bytes):
    off = 0
    while True:
        start = stream.find(START_MAGIC, off)
        if start < 0:
            return
        if start + 8 > len(stream):
            return
        frame_len = struct.unpack_from("<I", stream, start + 4)[0]
        if frame_len < 12 or start + frame_len > len(stream):
            off = start + 1
            continue
        frame = stream[start : start + frame_len]
        if frame[-4:] != END_MAGIC:
            off = start + 1
            continue

        pos = 8
        seq_raw, pos = read_varuint(frame, pos, 64)
        sequence = zigzag(seq_raw)
        packet_id, pos = read_varuint(frame, pos, 32)  # GetUshort()
        if pos >= len(frame) - 4:
            off = start + 1
            continue
        compressed = bool(frame[pos])
        pos += 1
        body_len_raw, pos = read_varuint(frame, pos, 32)
        body_len = zigzag(body_len_raw)  # PutOrGet(byte[]) -> GetInt()
        if body_len < 0 or pos + body_len > len(frame) - 4:
            off = start + 1
            continue
        body = frame[pos : pos + body_len]
        yield {
            "offset": start,
            "frame_len": frame_len,
            "sequence": sequence,
            "packet_id": packet_id,
            "compressed": compressed,
            "body": body,
        }
        off = start + frame_len


def xor_transform(data: bytes) -> bytes:
    """Reproduce Cs.Engine.Network.Buffer.Detail.Crypto.Encrypt on receive.

    Full 8-byte chunks are XORed with the current UInt64 mask (little endian).
    The game's final partial-block branch applies the low byte of the current
    mask to each remaining byte. Mask index advances per chunk and wraps at 4.
    """
    out = bytearray(data)
    off = 0
    mask_index = 0
    while off < len(out):
        mask = MASKS[mask_index]
        remaining = len(out) - off
        if remaining >= 8:
            mask_bytes = mask.to_bytes(8, "little")
            for j in range(8):
                out[off + j] ^= mask_bytes[j]
            off += 8
        else:
            low = mask & 0xFF
            for i in range(off, len(out)):
                out[i] ^= low
            off = len(out)
        mask_index = (mask_index + 1) % len(MASKS)
    return bytes(out)


def decode_transport_body(frame: Dict[str, Any]) -> bytes:
    if frame["compressed"]:
        return lz4.frame.decompress(frame["body"])
    return xor_transform(frame["body"])


# ---------------------------------------------------------------------------
# PacketReader-compatible schema decoder
# ---------------------------------------------------------------------------
class Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def need(self, n: int):
        if n < 0 or self.pos + n > len(self.data):
            raise DecodeError(f"Need {n} bytes at {self.pos}/{len(self.data)}")

    def byte(self):
        self.need(1)
        x = self.data[self.pos]
        self.pos += 1
        return x

    def boolean(self):
        return bool(self.byte())

    def varuint(self, max_bits=64):
        value = 0
        shift = 0
        while shift < max_bits:
            b = self.byte()
            value |= (b & 0x7F) << shift
            if not (b & 0x80):
                return value
            shift += 7
        raise DecodeError("Malformed PacketReader varint")

    def int32(self):
        return zigzag(self.varuint(32))

    def int64(self):
        return zigzag(self.varuint(64))

    def ushort(self):
        return self.varuint(32) & 0xFFFF

    def short(self):
        value = zigzag(self.varuint(32))
        return ((value + 32768) % 65536) - 32768

    def string(self):
        count = self.short()
        if count == -1:
            return None
        if count < 0:
            raise DecodeError(f"Invalid string length {count}")
        self.need(count)
        raw = self.data[self.pos : self.pos + count]
        self.pos += count
        return raw.decode("utf-8", errors="replace")

    def raw_long(self):
        self.need(8)
        value = struct.unpack_from("<q", self.data, self.pos)[0]
        self.pos += 8
        return value

    def float32(self):
        self.need(4)
        value = struct.unpack_from("<f", self.data, self.pos)[0]
        self.pos += 4
        return value

    def float64(self):
        self.need(8)
        value = struct.unpack_from("<d", self.data, self.pos)[0]
        self.pos += 8
        return value


def enum_values(schema, type_name: str):
    enums = schema["enums"]
    if type_name in enums:
        return enums[type_name]
    return enums.get(type_name.rsplit(".", 1)[-1], {})


def split_generic(type_name: str):
    match = re.match(r"^(List|HashSet)<(.+)>$", type_name.strip())
    return (match.group(1), match.group(2).strip()) if match else None


def decode_schema_packet(data: bytes, class_name: str, schema):
    reader = Reader(data)
    classes = schema["classes"]

    def decode_class(type_name: str):
        desc = classes.get(type_name)
        if not desc:
            raise DecodeError(f"Schema class not found: {type_name}")
        obj = {"$type": type_name}
        for field_name, kind in desc["order"]:
            field_type = desc["fields"][field_name]
            obj[field_name] = decode_value(field_type, kind)
        return obj

    def decode_message(type_name: str):
        if not reader.boolean():
            return None
        return decode_class(type_name)

    def enum_result(type_name: str, value: int):
        mapping = enum_values(schema, type_name)
        name = mapping.get(str(value)) if isinstance(mapping, dict) else None
        # Generated JSON keys are strings, but accept in-memory int maps too.
        if name is None and isinstance(mapping, dict):
            name = mapping.get(value)
        return {"value": value, "name": name}

    def decode_value(type_name: str, kind: str):
        type_name = type_name.strip()
        if kind == "enum":
            if type_name.startswith("List<"):
                inner = type_name[5:-1].strip()
                count = reader.ushort()
                return [enum_result(inner, reader.int32()) for _ in range(count)]
            return enum_result(type_name, reader.int32())

        if type_name == "bool":
            return reader.boolean()
        if type_name == "sbyte":
            x = reader.byte()
            return x - 256 if x > 127 else x
        if type_name == "byte":
            return reader.byte()
        if type_name == "short":
            return reader.short()
        if type_name == "ushort":
            return reader.ushort()
        if type_name == "int":
            return reader.int32()
        if type_name == "long":
            return reader.int64()
        if type_name == "float":
            return reader.float32()
        if type_name == "double":
            return reader.float64()
        if type_name == "string":
            return reader.string()
        if type_name in ("DateTime", "TimeSpan"):
            return reader.raw_long()
        if type_name == "byte[]":
            count = reader.int32()
            reader.need(count)
            raw = reader.data[reader.pos : reader.pos + count]
            reader.pos += count
            return raw.hex()
        if type_name == "int[]":
            count = reader.ushort()
            return [reader.int32() for _ in range(count)]
        if type_name.endswith("[]"):
            inner = type_name[:-2]
            count = reader.ushort()
            return [decode_message(inner) for _ in range(count)]

        generic = split_generic(type_name)
        if generic:
            _collection, inner = generic
            count = reader.ushort()
            if inner == "bool":
                return [reader.boolean() for _ in range(count)]
            if inner == "int":
                return [reader.int32() for _ in range(count)]
            if inner == "long":
                return [reader.int64() for _ in range(count)]
            if inner == "string":
                return [reader.string() for _ in range(count)]
            return [decode_message(inner) for _ in range(count)]

        return decode_message(type_name)

    obj = decode_class(class_name)  # top-level Extract uses GetWithoutNullBit
    return obj, reader.pos


# ---------------------------------------------------------------------------
# Normalization helpers
# ---------------------------------------------------------------------------
def ordered_values(obj: Optional[Dict[str, Any]], schema):
    if not isinstance(obj, dict) or "$type" not in obj:
        return []
    desc = schema["classes"].get(obj["$type"])
    if not desc:
        return []
    return [obj.get(field_name) for field_name, _kind in desc["order"]]


def enum_name(value):
    return value.get("name") if isinstance(value, dict) and "value" in value else None


def profile_from_player_info(player_info, schema):
    vals = ordered_values(player_info, schema)
    if not vals:
        return None
    profile = vals[0] if len(vals) > 0 else None
    guild = vals[1] if len(vals) > 1 else None
    pv = ordered_values(profile, schema)
    gv = ordered_values(guild, schema)
    if not pv:
        return None
    return {
        "uid": pv[1] if len(pv) > 1 else None,
        "name": pv[3] if len(pv) > 3 else None,
        "profile_text": pv[4] if len(pv) > 4 else None,
        "region": pv[18] if len(pv) > 18 else None,
        "guild": gv[1] if len(gv) > 1 else None,
    }


def normalize_stat(stat_obj, schema):
    vals = ordered_values(stat_obj, schema)
    if len(vals) < 2:
        return None
    enum_value = vals[0]
    if isinstance(enum_value, dict):
        stat_id = enum_value.get("value")
        stat_name = enum_value.get("name")
    else:
        stat_id = enum_value
        stat_name = None
    value_raw = vals[1]

    # Confirmed by client formatting logic + in-game verification:
    # these rate stats are stored as hundredths of one percentage point.
    # e.g. 220 -> 2.2%, 510 -> 5.1%.
    percent_stats = {
        "NST_NV_RATE_ATK",
        "NST_NV_RATE_HP",
        "NST_NV_RATE_DEF",
        "NST_RATE_CRITICAL",
        "NST_RATE_CRITICAL_DAMAGE",
        "NST_RATE_EFFECT_HIT",
        "NST_RATE_EFFECT_EVADE",
    }

    display_names = {
        "NST_ATK": "ATK",
        "NST_HP": "HP",
        "NST_DEF": "DEF",
        "NST_TURN_SPEED": "SPD",
        "NST_NV_RATE_ATK": "ATK",
        "NST_NV_RATE_HP": "HP",
        "NST_NV_RATE_DEF": "DEF",
        "NST_RATE_CRITICAL": "CRIT Rate",
        "NST_RATE_CRITICAL_DAMAGE": "CRIT DMG",
        "NST_RATE_EFFECT_HIT": "Effect Hit",
        "NST_RATE_EFFECT_EVADE": "Effect RES",
    }

    is_percent = stat_name in percent_stats

    return {
        "stat_id": stat_id,
        "stat": stat_name,
        "name": display_names.get(stat_name, stat_name),
        "value": round(value_raw * 0.01, 2) if is_percent else value_raw,
        "unit": "%" if is_percent else None,
        "value_raw": value_raw,
    }


def normalize_gear(gear_obj, schema):
    vals = ordered_values(gear_obj, schema)
    if len(vals) < 9:
        return {"raw": generic_numbered(gear_obj, schema)}
    return {
        "uid": vals[0],
        "template_id": vals[1],
        "level": vals[2],
        "level_raw": vals[2],
        "state_long_raw": vals[3],
        "flag_raw": vals[4],
        "main_stat": normalize_stat(vals[5], schema),
        "substats": [x for x in (normalize_stat(s, schema) for s in (vals[6] or [])) if x],
        "linked_unit_template_id": vals[7],
        "tail_int_raw": vals[8],
    }


def normalize_unit(unit_obj, schema):
    vals = ordered_values(unit_obj, schema)

    if len(vals) < 9:
        return {"raw": generic_numbered(unit_obj, schema)}

    # Preserve the complete decoded unit object by packet position.
    # This is deliberately kept even when we have a confident interpretation,
    # so fields can be reinterpreted later without recapturing the match.
    raw_fields = {
        f"f{i}": generic_numbered(v, schema)
        for i, v in enumerate(vals)
    }

    out = {
        "unit_kind": enum_name(vals[0]),
        "template_id": vals[1],

        # Exact raw packet representation.
        "raw_fields": raw_fields,

        # Keep this too for compatibility with older output/tools.
        "raw_ints": {
            "f2": vals[2] if len(vals) > 2 else None,
            "f3": vals[3] if len(vals) > 3 else None,
            "f4": vals[4] if len(vals) > 4 else None,
            "f5": vals[5] if len(vals) > 5 else None,
            "f6": vals[6] if len(vals) > 6 else None,
        },

        # Confirmed player-facing progression fields.
        "progression": {
            "level": vals[2] if len(vals) > 2 else None,
            "limit_break": vals[3] if len(vals) > 3 else None,
            "stellar_sigil_stage": vals[4] if len(vals) > 4 else None,
            "resonance_stage": vals[5] if len(vals) > 5 else None,
            "affection_level": vals[6] if len(vals) > 6 else None,
        },

        # Field 7: confirmed skill-level array.
        "skill_levels": (
            vals[7] if len(vals) > 7 and isinstance(vals[7], list) else []
        ),

        # Field 8.
        "equipment": [
            normalize_gear(g, schema)
            for g in ((vals[8] if len(vals) > 8 else None) or [])
            if g
        ],
    }

    # Field 9: Stellar Archive / Journey Stats.
    #
    # Packet order:
    #   0 Strength   / JST_POWER
    #   1 Vitality   / JST_HEALTH
    #   2 Endurance  / JST_ENDURANCE
    #   3 Focus      / JST_FOCUS
    #   4 Protection / JST_PROTECT
    if len(vals) > 9 and vals[9] is not None:
        journey_vals = ordered_values(vals[9], schema)

        # The nested object contains the List<int> as its first field.
        journey_list = (
            journey_vals[0]
            if journey_vals and isinstance(journey_vals[0], list)
            else []
        )

        out["stellar_archive_journey_stats"] = {
            "strength": journey_list[0] if len(journey_list) > 0 else None,
            "vitality": journey_list[1] if len(journey_list) > 1 else None,
            "endurance": journey_list[2] if len(journey_list) > 2 else None,
            "focus": journey_list[3] if len(journey_list) > 3 else None,
            "protection": journey_list[4] if len(journey_list) > 4 else None,
            "raw": journey_list,
        }
    else:
        out["stellar_archive_journey_stats"] = None

    # Field 10: Potential records.
    # We know what the records are, but keep their individual internals raw
    # until all Potential sub-fields are fully named.
    out["potentials_raw"] = [
        generic_numbered(p, schema)
        for p in ((vals[10] if len(vals) > 10 else None) or [])
    ]

    # Field 11.
    out["battle_unit_id"] = vals[11] if len(vals) > 11 else None

    # Fields 12-15 are now confirmed from battle code.
    out["battle_flags"] = {
        "is_leader": vals[12] if len(vals) > 12 else None,
        "is_boss": vals[13] if len(vals) > 13 else None,
        "is_elite": vals[14] if len(vals) > 14 else None,
        "is_ai_controlled": vals[15] if len(vals) > 15 else None,
    }

    # Field 16 is the battle team enum.
    if len(vals) > 16:
        team_raw = vals[16]
        out["team_side"] = {
            "value": (
                team_raw.get("value")
                if isinstance(team_raw, dict)
                else team_raw
            ),
            "name": enum_name(team_raw),
        }
    else:
        out["team_side"] = None

    # Field 20: Savior Adjust Type / alignment.
    if len(vals) > 20:
        adjust_raw = vals[20]
        out["adjust_type"] = {
            "value": (
                adjust_raw.get("value")
                if isinstance(adjust_raw, dict)
                else adjust_raw
            ),
            "name": enum_name(adjust_raw),
        }
    else:
        out["adjust_type"] = None

    # Field 18: derived stat contribution vector.
    #
    # Observed ranked PvP values consistently use known NKM stat indexes:
    #   0  = NST_HP
    #   2  = NST_ATK
    #   3  = NST_DEF
    #   12 = NST_NV_RATE_HP
    #   14 = NST_NV_RATE_ATK
    #   15 = NST_NV_RATE_DEF
    #
    # The exact upstream source/mechanic is not fully identified yet,
    # so keep the full raw vector alongside the interpreted values.
    if len(vals) > 18 and vals[18] is not None:
        f18_vals = ordered_values(vals[18], schema)

        stat_vector = (
            f18_vals[0]
            if f18_vals and isinstance(f18_vals[0], list)
            else []
        )

        def vec(index):
            return stat_vector[index] if len(stat_vector) > index else None

        out["derived_stat_vector"] = {
            "hp": vec(0),
            "atk": vec(2),
            "def": vec(3),

            "hp_rate": (
                round(vec(12) * 0.01, 2)
                if vec(12) is not None else None
            ),
            "atk_rate": (
                round(vec(14) * 0.01, 2)
                if vec(14) is not None else None
            ),
            "def_rate": (
                round(vec(15) * 0.01, 2)
                if vec(15) is not None else None
            ),

            "hp_rate_raw": vec(12),
            "atk_rate_raw": vec(14),
            "def_rate_raw": vec(15),

            "raw": stat_vector,
        }
    else:
        out["derived_stat_vector"] = None
    # We deliberately DO NOT assign meanings to these yet.
    #
    # f17 stat vectors
    # f19       = nested battle state
    # f21-f25   = still under investigation
    out["unmapped"] = {
        f"f{i}": generic_numbered(vals[i], schema)
        for i in [17, 19] + list(range(21, len(vals)))
    }

    return out


def normalize_side(side_obj, schema):
    vals = ordered_values(side_obj, schema)
    if len(vals) < 3:
        return {"raw": generic_numbered(side_obj, schema)}
    return {
        "team": enum_name(vals[0]),
        "profile": profile_from_player_info(vals[1], schema),
        "units": [normalize_unit(u, schema) for u in (vals[2] or []) if u],
    }


def generic_numbered(value, schema, depth=0):
    if depth > 12:
        return "<max-depth>"
    if isinstance(value, list):
        return [generic_numbered(v, schema, depth + 1) for v in value]
    if not isinstance(value, dict):
        return value
    if "value" in value and set(value.keys()).issubset({"value", "name"}):
        return value
    if "$type" not in value:
        return {k: generic_numbered(v, schema, depth + 1) for k, v in value.items()}
    vals = ordered_values(value, schema)
    out = {"_schema_type": value["$type"]}
    for i, v in enumerate(vals):
        out[f"f{i}"] = generic_numbered(v, schema, depth + 1)
    return out


def find_enum_name(value, names: set):
    if isinstance(value, dict):
        if value.get("name") in names:
            return value.get("name")
        for v in value.values():
            found = find_enum_name(v, names)
            if found:
                return found
    elif isinstance(value, list):
        for v in value:
            found = find_enum_name(v, names)
            if found:
                return found
    return None


def normalize_event(event_obj, frame_sequence: int, schema):
    vals = ordered_values(event_obj, schema)
    event_id = vals[0] if len(vals) > 0 else None
    event_enum = vals[1] if len(vals) > 1 else None
    payload = None
    payload_slot = None
    for idx, candidate in enumerate(vals[2:]):
        if candidate is not None:
            payload = generic_numbered(candidate, schema)
            payload_slot = idx
            break
    return {
        "event_id": event_id,
        "type_id": event_enum.get("value") if isinstance(event_enum, dict) else event_enum,
        "type": enum_name(event_enum),
        "frame_sequence": frame_sequence,
        "payload_slot": payload_slot,
        "payload": payload,
    }


def load_schema(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def packet_class_for_id(schema, packet_id: int):
    entry = schema["packet_ids"].get(str(packet_id))
    return entry["class"] if entry else None


def decode_known_frame(frame, schema):
    class_name = packet_class_for_id(schema, frame["packet_id"])
    if not class_name:
        return None, None
    body = decode_transport_body(frame)
    obj, consumed = decode_schema_packet(body, class_name, schema)
    if consumed != len(body):
        raise DecodeError(
            f"Packet {frame['packet_id']} decoded {consumed}/{len(body)} bytes"
        )
    return obj, body


def build_match(path: Path, schema):
    streams = reassemble_tcp(path)
    warnings = []
    frames = []
    for (src, dst, sport, dport), info in streams.items():
        if info["gaps"]:
            warnings.append(
                f"TCP gaps in {src}:{sport} -> {dst}:{dport}: {info['gaps']}"
            )
        for frame in iter_star_frames(info["data"]):
            frame = dict(frame)
            frame.update({"src": src, "dst": dst, "sport": sport, "dport": dport})
            frames.append(frame)

    packet_counts = Counter(f["packet_id"] for f in frames)
    self_uid = None
    start_obj = None
    end_obj = None
    events = []
    history_entries = None
    decode_failures = []

    # Decode only packets relevant to the normalized model. This avoids exposing
    # the ARENA_VERIFY connection key and keeps output stable.
    for frame in frames:
        pid = frame["packet_id"]
        if pid not in {
            PID_VERIFY_REQ,
            PID_ARENA_MATCH_NOT,
            PID_PVP_START_BATTLE_NOT,
            PID_BATTLE_NEXT_TURN_NOT,
            PID_BATTLE_END_NOT,
            PID_RANK_HISTORY_ACK,
        }:
            continue
        try:
            obj, _body = decode_known_frame(frame, schema)
            if obj is None:
                continue
            if pid == PID_VERIFY_REQ:
                vals = ordered_values(obj, schema)
                if vals:
                    self_uid = vals[0]  # deliberately discard connection key
            elif pid == PID_PVP_START_BATTLE_NOT:
                start_obj = obj
            elif pid == PID_BATTLE_NEXT_TURN_NOT:
                vals = ordered_values(obj, schema)
                for ev in (vals[0] if vals else []) or []:
                    if ev:
                        events.append(normalize_event(ev, frame["sequence"], schema))
            elif pid == PID_BATTLE_END_NOT:
                end_obj = obj
            elif pid == PID_RANK_HISTORY_ACK:
                vals = ordered_values(obj, schema)
                for value in vals:
                    if isinstance(value, list):
                        history_entries = len(value)
                        break
        except Exception as exc:
            decode_failures.append({
                "packet_id": pid,
                "sequence": frame["sequence"],
                "error": str(exc),
            })

    if start_obj is None:
        raise DecodeError("No decodable PVP_START_BATTLE_NOT (1609) found in capture")

    top_vals = ordered_values(start_obj, schema)
    match_state = top_vals[0] if top_vals else None
    ms_vals = ordered_values(match_state, schema)
    battle = ms_vals[4] if len(ms_vals) > 4 else None
    battle_vals = ordered_values(battle, schema)
    if len(battle_vals) < 7:
        raise DecodeError("PVP_START_BATTLE_NOT did not contain populated battle state")

    side_a = normalize_side(battle_vals[5], schema)
    side_b = normalize_side(battle_vals[6], schema)

    self_side = None
    opponent_side = None
    for side in (side_a, side_b):
        if self_uid is not None and side.get("profile", {}).get("uid") == self_uid:
            self_side = side
    if self_side is not None:
        opponent_side = side_b if self_side is side_a else side_a

    winner_team = None
    if end_obj is not None:
        result_name = find_enum_name(end_obj, {"AteamWin", "BteamWin", "Timeout"})
        if result_name == "AteamWin":
            winner_team = "Ateam"
        elif result_name == "BteamWin":
            winner_team = "Bteam"
        elif result_name == "Timeout":
            winner_team = None

    won = None
    if self_side and winner_team:
        won = self_side.get("team") == winner_team

    match_id = battle_vals[0] if battle_vals else None
    battle_type = enum_name(battle_vals[2]) if len(battle_vals) > 2 else None
    map_name = battle_vals[4] if len(battle_vals) > 4 else None

    result = {
        "format": "starsavior-match-v0.1",
        "source": path.name,
        "match": {
            "match_id": match_id,
            "battle_type": battle_type,
            "map": map_name,
            "winner_team": winner_team,
            "self_won": won,
        },
        "self": self_side,
        "opponent": opponent_side,
        "sides": {"Ateam": side_a, "Bteam": side_b},
        "battle_events": events,
        "battle_event_counts": dict(Counter(e.get("type") or str(e.get("type_id")) for e in events)),
        "rank_history": {
            "history_ack_seen": packet_counts.get(PID_RANK_HISTORY_ACK, 0) > 0,
            "entries_in_ack": history_entries,
        },
        "capture": {
            "star_frames": len(frames),
            "packet_counts": {str(k): v for k, v in sorted(packet_counts.items())},
            "tcp_streams": len(streams),
            "warnings": warnings,
            "decode_failures": decode_failures,
        },
        "notes": {
            "gear_stat_values": "value_raw is preserved exactly. Confirmed percentage-type gear stats also include display value = value_raw * 0.01.",
            "unit_raw_ints": "f2-f6 are preserved until their exact UI semantics are mapped.",
            "privacy": "ARENA_VERIFY connection/session key is intentionally not written to JSON.",
        },
    }

    # v0.3 enrichment is deliberately best-effort: packet decoding still
    # succeeds even if the local game master-data lookup needs refreshing.
    try:
        from lookups import enrich_match
        enrich_match(result, Path(__file__).resolve().parent)
    except Exception as exc:
        result["format"] = "starsavior-match-v0.3"
        result.setdefault("lookup", {})
        result["lookup"]["warning"] = str(exc)

    return result


def main():
    parser = argparse.ArgumentParser(description="Decode and enrich a StarSavior PvP PCAPNG into match JSON")
    parser.add_argument("pcapng", type=Path, help="clean/full .pcapng capture")
    parser.add_argument("-o", "--output", type=Path, default=Path("match.json"))
    parser.add_argument(
        "--schema",
        type=Path,
        default=Path(__file__).with_name("schema.json"),
        help="schema snapshot (default: schema.json next to script)",
    )
    args = parser.parse_args()

    try:
        schema = load_schema(args.schema)
        result = build_match(args.pcapng, schema)
        args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print(f"Decoded: {args.pcapng}")
    print(f"Output:  {args.output}")
    opp = result.get("opponent") or {}
    prof = opp.get("profile") or {}
    print(f"Opponent: {prof.get('name') or '<unknown>'} [{prof.get('region') or '?'}]")
    units = opp.get("units") or []
    print(f"Opponent units: {len(units)}")
    names = [u.get("display_name") or u.get("name") or str(u.get("template_id")) for u in units]
    if names:
        print(f"Opponent team: {", ".join(names)}")
    gear_count = sum(len(u.get("equipment") or []) for u in units)
    print(f"Opponent gear: {gear_count}")
    lookup_warning = (result.get("lookup") or {}).get("warning")
    if lookup_warning:
        print(f"Lookup warning: {lookup_warning}")
    print(f"Battle events: {len(result.get('battle_events') or [])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
