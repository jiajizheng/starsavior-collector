#!/usr/bin/env python3
"""Static master-data lookup/enrichment for the StarSavior PvP collector.

This module:
- reads ONLY two known installed-game bundles in memory;
- decrypts only their UnityFS headers/first 100 KiB as required;
- extracts UNIT_TEMPLET + STRING_COMMON TextAssets;
- writes a small cached unit lookup under lookups/units.json;
- uses equip-sets.json for equipment/set names and metadata.

No Frida, process injection, memory reading, packet modification, or TLS MITM.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import io
import json
import os
import re
import struct
import warnings
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

import lz4.block
import lz4.frame

UNITY_VERSION = "6000.0.61f1"
TEMPLET_MAGIC = 0x2B21DE00

DEFAULT_EB_DIR = Path(
    r"C:\Program Files (x86)\Steam\steamapps\common\StarSavior\Data\eb"
)

# Identified from the user's current installed build on 2026-09-01.
UNIT_MASTER_BUNDLE = "acda0720b289f558c546ef8c82f3e116a8860f7e.bundle"
STRING_COMMON_BUNDLE = "3d90eef225cf913b5e39e8ac0edbc59d8de9fa2d.bundle"

KNOWN_PLAINTEXT = bytes(
    [0x55, 0x6E, 0x69, 0x74, 0x79, 0x46, 0x53, 0x00,
     0x00, 0x00, 0x00, 0x08, 0x35, 0x2E, 0x78, 0x2E]
)
TYPE1_KEY = bytes([0xFF, 0xBB, 0xCC, 0x21])
ENCRYPTION_LIMIT = 102400

SLOT_NAMES = {
    "WEAPON": "Weapon",
    "GLOVES": "Gloves",
    "ARMOR": "Armor",
    "SHOES": "Shoes",
    "NECKLACE": "Necklace",
    "RING": "Ring",
}

VARIANT_MARKERS = {
    "SUMMER": "Summer",
    "WEDDING": "Wedding",
    "DRESS": "Dress",
    "HALLOWEEN": "Halloween",
    "CHRISTMAS": "Christmas",
    "XMAS": "Christmas",
    "NEWYEAR": "New Year",
    "VALENTINE": "Valentine",
}


class LookupError(RuntimeError):
    pass


def _derive_bundle_key(bundle_name: str) -> bytes:
    return hashlib.md5((bundle_name[:32] + ".bytes").encode("utf-8")).digest()


def _derived_plaintext_key(first16: bytes) -> bytes:
    return bytes(e ^ p for e, p in zip(first16[:16], KNOWN_PLAINTEXT))


def decrypt_bundle(data: bytes, bundle_name: str) -> bytes:
    """Decrypt a StarSavior bundle in memory without writing a second copy."""
    if len(data) < 16 or data[:7] == b"UnityFS":
        return data

    first16 = data[:16]
    if _derived_plaintext_key(first16) == TYPE1_KEY * 4:
        key = TYPE1_KEY
        limit = 128
    else:
        key = _derive_bundle_key(bundle_name)
        limit = ENCRYPTION_LIMIT

    result = bytearray(data)
    end = min(len(result), limit)
    for i in range(end):
        result[i] ^= key[i % len(key)]
    return bytes(result)


def _extract_textassets(bundle_data: bytes) -> Dict[str, bytes]:
    """Read raw TextAsset bytes from an already-decrypted UnityFS bundle."""
    try:
        import UnityPy
    except ImportError as exc:
        raise LookupError("UnityPy is required to build the unit lookup; install requirements.txt") from exc

    UnityPy.config.FALLBACK_UNITY_VERSION = UNITY_VERSION

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        env = UnityPy.load(io.BytesIO(bundle_data))

    result: Dict[str, bytes] = {}
    for obj in env.objects:
        if obj.type.name != "TextAsset":
            continue
        try:
            raw = obj.get_raw_data()
            if not raw or len(raw) < 8:
                continue

            name_len = struct.unpack_from("<I", raw, 0)[0]
            name_start = 4
            name_end = name_start + name_len
            if name_end > len(raw):
                continue

            name = raw[name_start:name_end].decode("utf-8", errors="replace")
            pos = (name_end + 3) & ~3
            if pos + 4 > len(raw):
                continue

            script_len = struct.unpack_from("<I", raw, pos)[0]
            script_start = pos + 4
            script_end = script_start + script_len
            if script_end > len(raw):
                continue

            result[name] = raw[script_start:script_end]
        except Exception:
            continue
    return result


def _templet_mask(filename: str) -> bytes:
    if not filename.endswith(".bytes"):
        filename += ".bytes"
    return hashlib.md5(filename.encode("utf-8")).digest()



def _decompress_lz4_frame_blocks(packed: bytes) -> bytes:
    """Fallback LZ4-frame decoder for updated StarSavior template assets.

    The Sep 3 2026 STRING_COMMON frame is structurally valid LZ4, but some
    compressed blocks fail through python-lz4's high-level frame decoder.
    Decoding the same independent blocks with a larger destination buffer
    succeeds and reconstructs valid UTF-8/JSON.

    This fallback intentionally supports only independent-block LZ4 frames,
    which is what the game's affected template currently uses.
    """
    if len(packed) < 7 or packed[:4] != b"\x04\x22\x4d\x18":
        raise LookupError("LZ4 fallback: invalid frame magic/header")

    flg = packed[4]
    bd = packed[5]

    # LZ4 frame version must be 01b.
    if (flg >> 6) != 1:
        raise LookupError(f"LZ4 fallback: unsupported frame version in FLG {flg:#04x}")

    block_independent = bool(flg & 0x20)
    block_checksum = bool(flg & 0x10)
    content_size_flag = bool(flg & 0x08)
    content_checksum = bool(flg & 0x04)
    dict_id_flag = bool(flg & 0x01)

    if not block_independent:
        raise LookupError("LZ4 fallback: linked-block frames are not supported")

    # BD bits 6:4 map to the standard max block sizes.
    block_size_code = (bd >> 4) & 0x07
    max_block_size = {
        4: 64 * 1024,
        5: 256 * 1024,
        6: 1024 * 1024,
        7: 4 * 1024 * 1024,
    }.get(block_size_code)
    if max_block_size is None:
        raise LookupError(f"LZ4 fallback: unsupported BD {bd:#04x}")

    # Frame header: magic + FLG + BD + optional fields + HC byte.
    pos = 6
    if content_size_flag:
        if pos + 8 > len(packed):
            raise LookupError("LZ4 fallback: truncated content-size field")
        pos += 8
    if dict_id_flag:
        if pos + 4 > len(packed):
            raise LookupError("LZ4 fallback: truncated dictionary-id field")
        pos += 4
    if pos >= len(packed):
        raise LookupError("LZ4 fallback: truncated header checksum")
    pos += 1  # HC

    parts = []
    while True:
        if pos + 4 > len(packed):
            raise LookupError("LZ4 fallback: truncated block header")

        raw_size = struct.unpack_from("<I", packed, pos)[0]
        pos += 4

        if raw_size == 0:
            break

        is_raw = bool(raw_size & 0x80000000)
        block_size = raw_size & 0x7FFFFFFF

        if block_size <= 0 or block_size > max_block_size:
            raise LookupError(
                f"LZ4 fallback: invalid block size {block_size} "
                f"(max {max_block_size})"
            )
        if pos + block_size > len(packed):
            raise LookupError("LZ4 fallback: truncated block payload")

        block = packed[pos : pos + block_size]
        pos += block_size

        if is_raw:
            out = block
        else:
            # Some updated STRING_COMMON blocks still expand to 64 KiB but need
            # a larger destination capacity than python-lz4's exact-size path.
            # 2x the advertised max is sufficient for the affected 64 KiB
            # frames and remains bounded for larger standard LZ4 block sizes.
            out = lz4.block.decompress(
                block,
                uncompressed_size=max_block_size * 2,
            )

        parts.append(out)

        if block_checksum:
            if pos + 4 > len(packed):
                raise LookupError("LZ4 fallback: truncated block checksum")
            pos += 4

    if content_checksum:
        if pos + 4 > len(packed):
            raise LookupError("LZ4 fallback: truncated content checksum")
        pos += 4

    if pos != len(packed):
        raise LookupError(
            f"LZ4 fallback: trailing bytes after frame ({len(packed) - pos})"
        )

    return b"".join(parts)


def decrypt_templet(data: bytes, filename: str) -> str:
    if len(data) <= 4:
        raise LookupError(f"{filename}: templet is too short")

    magic = struct.unpack_from("<i", data, 0)[0]
    if (magic & 0xFFFFFF00) != TEMPLET_MAGIC:
        raise LookupError(f"{filename}: unexpected templet magic {magic:#010x}")

    version = magic & 0xFF
    body = data[4:]

    if version in (0, 1):
        packed = body
    elif version == 2:
        mask = _templet_mask(filename)
        packed = bytes(b ^ mask[i % len(mask)] for i, b in enumerate(body))
    else:
        raise LookupError(f"{filename}: unsupported templet version {version}")

    try:
        try:
            unpacked = lz4.frame.decompress(packed)
        except Exception:
            unpacked = _decompress_lz4_frame_blocks(packed)
        return unpacked.decode("utf-8-sig")
    except Exception as exc:
        raise LookupError(f"{filename}: LZ4/UTF-8 decode failed: {exc}") from exc


def _jsonish_load(text: str) -> Any:
    """Load generated game JSON while tolerating trailing commas."""
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        cleaned = re.sub(r",(\s*[}\]])", r"\1", text)
        return json.loads(cleaned)


def _pretty_enum(value: Any, prefix: str = "") -> Optional[str]:
    if not isinstance(value, str) or not value:
        return None
    if prefix and value.startswith(prefix):
        value = value[len(prefix):]
    return value.replace("_", " ").title()


def _infer_variant(internal_id: Optional[str]) -> Optional[str]:
    if not internal_id:
        return None
    tokens = set(internal_id.upper().split("_"))
    for token, label in VARIANT_MARKERS.items():
        if token in tokens:
            return label
    return None


def _read_localized_keys(text: str, targets: set[str]) -> Dict[str, str]:
    """Extract only requested Key -> Value_ENG entries from STRING_COMMON."""
    found: Dict[str, str] = {}
    current: Optional[str] = None

    key_re = re.compile(r'^\s*"Key"\s*:\s*(.+?)\s*,?\s*$')
    eng_re = re.compile(r'^\s*"Value_ENG"\s*:\s*(.+?)\s*,?\s*$')

    for line in text.splitlines():
        m = key_re.match(line)
        if m:
            try:
                key = json.loads(m.group(1).rstrip(","))
            except Exception:
                current = None
                continue
            current = key if key in targets else None
            continue

        if current is not None:
            m = eng_re.match(line)
            if m:
                try:
                    value = json.loads(m.group(1).rstrip(","))
                    found[current] = value
                except Exception:
                    pass
                current = None

        if len(found) == len(targets):
            break

    return found


def _resolve_eb_dir() -> Path:
    override = os.environ.get("STARSAVIOR_EB_DIR")
    return Path(override) if override else DEFAULT_EB_DIR



def _discover_master_bundles(eb_dir: Path) -> tuple[Path, Path]:
    """Find current UNIT_TEMPLET and STRING_COMMON bundles after a game update.

    Fast path uses the known hashes above. If either file disappeared, scan the
    installed bundles and identify them by their contained TextAsset names.
    """
    unit_bundle = eb_dir / UNIT_MASTER_BUNDLE
    string_bundle = eb_dir / STRING_COMMON_BUNDLE

    if unit_bundle.exists() and string_bundle.exists():
        return unit_bundle, string_bundle

    found_unit = unit_bundle if unit_bundle.exists() else None
    found_string = string_bundle if string_bundle.exists() else None

    # New/changed bundles are usually among the most recently modified files,
    # so inspect those first while still falling back to a complete scan.
    bundles = list(eb_dir.glob("*.bundle"))
    bundles.sort(key=lambda p: p.stat().st_mtime, reverse=True)

    for path in bundles:
        if found_unit is not None and found_string is not None:
            break
        try:
            dec = decrypt_bundle(path.read_bytes(), path.stem)
            assets = _extract_textassets(dec)
        except Exception:
            continue

        names = set(assets)
        if found_unit is None and any(
            name.startswith("CLIENT_UNIT_TEMPLET_BASE") for name in names
        ):
            found_unit = path

        if found_string is None and "STRING_COMMON" in names:
            found_string = path

    if found_unit is None:
        raise LookupError(
            f"Could not discover the current unit master bundle under {eb_dir}."
        )
    if found_string is None:
        raise LookupError(
            f"Could not discover the current STRING_COMMON bundle under {eb_dir}."
        )

    return found_unit, found_string


def build_unit_lookup(base_dir: Path) -> Dict[str, Any]:
    """Build/cache the character lookup from the current installed game."""
    base_dir = Path(base_dir)
    cache_dir = base_dir / "lookups"
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_path = cache_dir / "units.json"

    eb_dir = _resolve_eb_dir()
    unit_bundle, string_bundle = _discover_master_bundles(eb_dir)

    unit_dec = decrypt_bundle(unit_bundle.read_bytes(), unit_bundle.stem)
    unit_assets = _extract_textassets(unit_dec)

    records: Dict[str, dict] = {}
    localization_keys: set[str] = set()

    for asset_name, asset_data in unit_assets.items():
        if not asset_name.startswith("CLIENT_UNIT_TEMPLET_BASE"):
            continue
        text = decrypt_templet(asset_data, asset_name)
        obj = _jsonish_load(text)
        rows = obj.get("Data", []) if isinstance(obj, dict) else []
        for row in rows:
            if not isinstance(row, dict):
                continue
            unit_id = row.get("m_UnitID")
            if not isinstance(unit_id, int):
                continue
            records[str(unit_id)] = row
            for key_name in ("m_UnitNameString", "m_UnitTitleString"):
                k = row.get(key_name)
                if isinstance(k, str) and k:
                    localization_keys.add(k)

    string_dec = decrypt_bundle(string_bundle.read_bytes(), string_bundle.stem)
    string_assets = _extract_textassets(string_dec)
    string_raw = string_assets.get("STRING_COMMON")
    if string_raw is None:
        raise LookupError("STRING_COMMON TextAsset was not found in its bundle.")

    string_text = decrypt_templet(string_raw, "STRING_COMMON")
    localized = _read_localized_keys(string_text, localization_keys)

    units: Dict[str, dict] = {}
    for unit_id, row in records.items():
        internal_id = row.get("m_UnitStrID")
        name_key = row.get("m_UnitNameString")
        title_key = row.get("m_UnitTitleString")
        name = localized.get(name_key, name_key)
        title = localized.get(title_key, title_key)
        variant = _infer_variant(internal_id)

        display_name = name
        if name and variant:
            display_name = f"{name} ({variant})"

        units[unit_id] = {
            "name": name,
            "display_name": display_name,
            "variant": variant,
            "name_key": name_key,
            "title": title,
            "title_key": title_key,
            "internal_id": internal_id,
            "character_category_id": row.get("CharacterCategoryNum"),
            "rarity": row.get("UnitGrade"),
            "unit_kind": _pretty_enum(row.get("m_NKM_UNIT_TYPE"), "NUT_"),
            "role": _pretty_enum(row.get("m_NKM_UNIT_ROLE_TYPE"), "NURT_"),
            "role_subtype": _pretty_enum(
                row.get("m_NKM_UNIT_ROLE_SUB_TYPE"), "NURST_"
            ),
            "adjust_type": _pretty_enum(row.get("NKM_UNIT_ADJUST_TYPE"), "NUAT_"),
            "attack_tag": _pretty_enum(row.get("UnitAttackTagType"), "UAT_"),
            "stat_profile": row.get("m_StatStrID"),
            "portrait": row.get("m_UnitFace"),
        }

    payload = {
        "format": "starsavior-unit-lookups-v0.3",
        "generated_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "source_bundles": {
            "unit_master": unit_bundle.name,
            "string_common": string_bundle.name,
        },
        "units": units,
    }
    cache_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return payload


def load_unit_lookup(base_dir: Path, required_ids: Iterable[int] = ()) -> Dict[str, Any]:
    base_dir = Path(base_dir)
    cache_path = base_dir / "lookups" / "units.json"

    payload: Optional[Dict[str, Any]] = None
    if cache_path.exists():
        try:
            payload = json.loads(cache_path.read_text(encoding="utf-8"))
        except Exception:
            payload = None

    required = {str(x) for x in required_ids if isinstance(x, int)}
    available = set((payload or {}).get("units", {}).keys())

    # Rebuild only when no cache exists or it cannot satisfy this match.
    if payload is None or not required.issubset(available):
        payload = build_unit_lookup(base_dir)

    return payload


def load_equipment_lookup(base_dir: Path) -> Dict[str, Any]:
    path = Path(base_dir) / "equip-sets.json"
    if not path.exists():
        raise LookupError(f"Equipment lookup file not found: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    required = {"items", "sets", "itemInfo", "models", "grades"}
    missing = required - set(data)
    if missing:
        raise LookupError(f"equip-sets.json is missing keys: {sorted(missing)}")
    return data


def _localized(obj: Any, locale: str = "en") -> Any:
    if isinstance(obj, dict):
        return obj.get(locale) or obj.get("en")
    return obj


def equipment_metadata(equip_db: Dict[str, Any], template_id: int) -> Optional[dict]:
    key = str(template_id)
    item_info = equip_db.get("itemInfo", {}).get(key)
    if not isinstance(item_info, dict):
        return None

    model = item_info.get("model")
    model_info = equip_db.get("models", {}).get(model, {})
    grade_key = item_info.get("grade")
    grade = _localized(equip_db.get("grades", {}).get(grade_key, {}))

    set_id = equip_db.get("items", {}).get(key)
    set_info = equip_db.get("sets", {}).get(str(set_id), {}) if set_id is not None else {}

    set_obj = None
    if set_id is not None:
        params = set_info.get("params") or []
        desc_template = _localized(set_info.get("desc", {}))
        description = desc_template
        if isinstance(desc_template, str):
            try:
                description = desc_template.format(*params)
            except Exception:
                pass

        set_obj = {
            "id": set_id,
            "name": _localized(set_info.get("name", {})),
            "pieces_required": set_info.get("needParts"),
            "description": description,
            "stats": set_info.get("stats"),
        }

    slot = None
    family = None
    if isinstance(model, str):
        final = model.rsplit("_", 1)[-1]
        slot = SLOT_NAMES.get(final)
        family = model.split("_TIER_", 1)[0].replace("_", " ").title()

    return {
        "name": _localized(model_info.get("name", {})),
        "model": model,
        "family": family,
        "slot": slot,
        "tier": item_info.get("tier"),
        "grade": grade or grade_key,
        "set": set_obj,
        "icon": model_info.get("icon"),
    }


def _collect_unit_ids(result: dict) -> set[int]:
    ids: set[int] = set()
    for side_name in ("self", "opponent"):
        side = result.get(side_name)
        if not isinstance(side, dict):
            continue
        for unit in side.get("units") or []:
            if isinstance(unit, dict) and isinstance(unit.get("template_id"), int):
                ids.add(unit["template_id"])
    for side in (result.get("sides") or {}).values():
        if not isinstance(side, dict):
            continue
        for unit in side.get("units") or []:
            if isinstance(unit, dict) and isinstance(unit.get("template_id"), int):
                ids.add(unit["template_id"])
    return ids


def enrich_match(result: dict, base_dir: Path) -> dict:
    """Add readable unit/equipment metadata while preserving raw IDs/values."""
    base_dir = Path(base_dir)
    unit_ids = _collect_unit_ids(result)

    unit_payload = load_unit_lookup(base_dir, unit_ids)
    units_db = unit_payload.get("units", {})
    equip_db = load_equipment_lookup(base_dir)

    missing_units: set[int] = set()
    missing_equipment: set[int] = set()
    seen_sides: set[int] = set()

    def enrich_side(side: Any) -> None:
        if not isinstance(side, dict) or id(side) in seen_sides:
            return
        seen_sides.add(id(side))

        for unit in side.get("units") or []:
            if not isinstance(unit, dict):
                continue

            unit_id = unit.get("template_id")
            meta = units_db.get(str(unit_id)) if isinstance(unit_id, int) else None
            if isinstance(meta, dict):
                unit["name"] = meta.get("name")
                unit["display_name"] = meta.get("display_name") or meta.get("name")
                unit["character"] = meta
            elif isinstance(unit_id, int):
                missing_units.add(unit_id)

            for gear in unit.get("equipment") or []:
                if not isinstance(gear, dict):
                    continue
                gear_id = gear.get("template_id")
                if not isinstance(gear_id, int):
                    continue

                # v0.1 used a conservative field name. We now have a verified
                # enhancement-level interpretation, but retain level_raw too.
                if "level_raw" in gear:
                    gear["level"] = gear.get("level_raw")

                gmeta = equipment_metadata(equip_db, gear_id)
                if gmeta is None:
                    missing_equipment.add(gear_id)
                    continue

                # Keep the original template_id and packet-derived stats.
                gear.update(gmeta)

    enrich_side(result.get("self"))
    enrich_side(result.get("opponent"))
    for side in (result.get("sides") or {}).values():
        enrich_side(side)

    result["lookup"] = {
        "unit_source": "installed StarSavior client master data",
        "unit_cache": "lookups/units.json",
        "equipment_source": "equip-sets.json",
        "missing_unit_template_ids": sorted(missing_units),
        "missing_equipment_template_ids": sorted(missing_equipment),
    }
    result["format"] = "starsavior-match-v0.3"
    return result
