# StarSavior PvP passive collector — v0.3

v0.3 keeps the passive capture/decode flow from v0.2 and adds readable
character/equipment metadata.

## New in v0.3

- fixes the CLI `Opponent gear: 0` bug (`equipment`, not `gear`)
- preserves equipment `template_id` and all packet-derived raw stat values
- adds verified `level` while retaining `level_raw` for compatibility
- enriches character IDs from the installed client's unit master tables
- enriches equipment IDs from `equip-sets.json`
- adds equipment name, family, slot, tier, grade, and set metadata
- caches character mappings in `lookups/units.json`
- does not write decrypted game bundles to disk

The lookup path is static only. It does not use Frida, inject into the game,
read game memory, alter packets, or bypass anti-cheat.

## Install/update

Copy/unzip these files into:

`C:\dev\starsavior-collector`

Then make sure the venv has:

```powershell
.\.venv\Scripts\python.exe -m pip install -r .\requirements.txt
```

## Run one match

```powershell
.\.venv\Scripts\python.exe .\collect.py
```

On the first enriched decode, the collector reads two known game bundles from
the installed StarSavior client and creates the small cache
`lookups\units.json`. It does not decrypt the full bundle directory.

Default game bundle directory:

`C:\Program Files (x86)\Steam\steamapps\common\StarSavior\Data\eb`

If your game is installed elsewhere, set `STARSAVIOR_EB_DIR` before running.

## Manual decode

```powershell
.\.venv\Scripts\python.exe .\decode_match.py `
    .\captures\your-capture.pcapng `
    -o .\research\match-v03.json
```

## Output example

A unit now looks like:

```json
{
  "template_id": 1045,
  "name": "Luna",
  "display_name": "Luna (Summer)",
  "character": {
    "rarity": "SSR",
    "role": "Defender",
    "internal_id": "NKM_UNIT_S_SUMMER_ORACLE"
  }
}
```

Equipment keeps the original ID and live packet stats, while adding lookup
metadata:

```json
{
  "template_id": 510920301,
  "name": "Royal Guard's Greatsword",
  "family": "Perses",
  "slot": "Weapon",
  "tier": 2,
  "grade": "Legendary",
  "level": 15,
  "set": {
    "id": 9,
    "name": "Health Set",
    "pieces_required": 4
  }
}
```

## Build compatibility

The two current master-data bundle hashes were identified against the installed
2026-09-01 client build. If a later game update replaces those bundles,
packet decoding will still work, but `lookup.warning` will explain that lookup
bundle discovery needs to be refreshed.
