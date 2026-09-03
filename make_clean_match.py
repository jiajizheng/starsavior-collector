#!/usr/bin/env python3
import argparse
import json
from pathlib import Path


def clean_equipment(eq):
    keep = (
        "uid",
        "template_id",
        "level",
        "name",
        "model",
        "family",
        "slot",
        "tier",
        "grade",
        "set",
        "main_stat",
        "substats",
        "linked_unit_template_id",
        "icon",
    )
    return {k: eq[k] for k in keep if k in eq}


def clean_potential(p):
    if not isinstance(p, dict):
        return {"raw": p}
    return {
        "potential_id": p.get("f0"),
        "level": p.get("f1"),
        "sale_index": p.get("f2"),
        "standard_blessing_level": p.get("f3"),
    }


def clean_unit(unit):
    out = {
        "name": unit.get("display_name") or unit.get("name"),
        "template_id": unit.get("template_id"),
        "character": unit.get("character"),
        "progression": unit.get("progression"),
        "skill_levels": unit.get("skill_levels"),
        "stellar_archive": unit.get("stellar_archive_journey_stats"),
        "derived_stat_vector": unit.get("derived_stat_vector"),
        "battle_unit_id": unit.get("battle_unit_id"),
        "battle_flags": unit.get("battle_flags"),
        "team_side": unit.get("team_side"),
        "adjust_type": unit.get("adjust_type"),
        "equipment": [clean_equipment(x) for x in unit.get("equipment", [])],
    }

    potentials = unit.get("potentials_raw") or []
    if potentials:
        out["potentials"] = [clean_potential(p) for p in potentials]

    return {k: v for k, v in out.items() if v is not None}


def clean_side(side):
    return {
        "team": side.get("team"),
        "profile": side.get("profile"),
        "units": [clean_unit(u) for u in side.get("units", [])],
    }



def _enum_name(value):
    if isinstance(value, dict):
        return value.get("name")
    return value


def clean_battle_event(event, unit_index=None):
    out = {
        "event_id": event.get("event_id"),
        "type_id": event.get("type_id"),
        "type": event.get("type"),
        "frame_sequence": event.get("frame_sequence"),
    }

    payload = event.get("payload") or {}
    etype = event.get("type")
    battle_unit_id = None

    if etype == "SelectTurnUnit":
        # payload.f0 = selected battle unit id
        battle_unit_id = payload.get("f0")
        out["battle_unit_id"] = battle_unit_id

    elif etype == "DoSkill":
        # payload.f0 = acting battle unit id
        # payload.f1 = action / attack type enum
        # payload.f2 = skill enum
        battle_unit_id = payload.get("f0")
        out["battle_unit_id"] = battle_unit_id
        out["action_type"] = _enum_name(payload.get("f1"))
        out["skill"] = _enum_name(payload.get("f2"))

    elif etype == "BattleResult":
        # payload.f0.f0 = winner enum
        state = payload.get("f0") or {}
        out["winner"] = _enum_name(state.get("f0"))

    # Enrich any event carrying a mapped battle_unit_id.
    if battle_unit_id is not None and unit_index:
        info = unit_index.get(battle_unit_id)
        if info:
            out["unit"] = info.get("name")
            out["side"] = info.get("side")
            out["template_id"] = info.get("template_id")

    # WaveStart and unknown event types intentionally keep metadata only
    # until more payload fields are mapped confidently.

    return {k: v for k, v in out.items() if v is not None}


def build_battle_unit_index(data):
    index = {}
    for side_name in ("self", "opponent"):
        side = data.get(side_name) or {}
        for unit in side.get("units", []):
            battle_unit_id = unit.get("battle_unit_id")
            if battle_unit_id is None:
                continue
            index[battle_unit_id] = {
                "name": unit.get("display_name") or unit.get("name"),
                "side": side_name,
                "template_id": unit.get("template_id"),
            }
    return index

def make_clean(data):
    unit_index = build_battle_unit_index(data)

    out = {
        "format": "starsavior-match-clean-v0.3",
        "source": data.get("source"),
        "match": data.get("match"),
        "ranked_rating": (
            {
                "before": (data.get("ranked_rating") or {}).get("before"),
                "after": (data.get("ranked_rating") or {}).get("after"),
                "change": (data.get("ranked_rating") or {}).get("change"),
            }
            if data.get("ranked_rating") is not None
            else None
        ),
        "self": clean_side(data.get("self") or {}),
        "opponent": clean_side(data.get("opponent") or {}),
        "battle_event_counts": data.get("battle_event_counts"),
        "battle_events": [
            clean_battle_event(e, unit_index)
            for e in (data.get("battle_events") or [])
        ],
    }
    return {k: v for k, v in out.items() if v is not None}


def main():
    ap = argparse.ArgumentParser(description="Create a clean StarSavior analytics JSON.")
    ap.add_argument("input", type=Path, help="Full decoded match JSON")
    ap.add_argument("-o", "--output", type=Path, help="Output clean JSON")
    args = ap.parse_args()

    data = json.loads(args.input.read_text(encoding="utf-8"))
    clean = make_clean(data)

    out = args.output or args.input.with_name(args.input.stem + "-clean.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(clean, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Clean JSON written to: {out}")


if __name__ == "__main__":
    main()
