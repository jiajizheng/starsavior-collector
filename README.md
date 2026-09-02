# StarSavior PvP Collector

A small Windows tool for **passively capturing and decoding StarSavior ranked PvP match data**.

The collector is intended for volunteers who want to contribute PvP build data for analysis. It captures one match at a time, decodes the match locally, and produces a clean JSON file containing the opponent/team/build information.

## What it collects

For a successfully decoded ranked PvP match, the clean JSON can include:

- match ID, map, result, and team side
- player/opponent profile information exposed in the PvP protocol
- the 4 units on each side
- character metadata such as name, rarity, role, subtype, and element/adjust type
- battle/applied level
- Limit Break
- Stellar Sigil stage
- Resonance stage
- Affection level
- skill-level array
- Stellar Archive Journey stats
- equipment names, slots, sets, enhancement levels, main stats, and substats
- Potential records
- a small battle-event summary

Battle events are retained for now but are not required for the main build-data use case.

## Privacy / safety

This collector uses **passive packet capture only**.

It does **not**:

- inject into StarSavior
- modify the game client
- modify packets
- read game process memory
- use Frida
- bypass anti-cheat
- bypass TLS/certificate pinning

The capture filter is restricted to the TCP port range currently used by the game's PvP services:

```text
tcp portrange 9300-9400
```

The raw `.pcapng` capture is saved locally for troubleshooting. **Do not send the raw PCAP unless you intentionally want to provide it for debugging.**

For normal data contribution, send only the generated:

```text
*-clean.json
```

The decoder does not include the Arena connection/session key in the clean exported match data.

## Requirements

Windows is currently the supported platform.

Install:

1. **Python 3.11 or newer**
   - During installation, enable **Add Python to PATH**.
2. **Wireshark**
   - Make sure **Npcap** is installed when prompted.
3. **StarSavior via Steam**

TShark is normally detected automatically from:

```text
C:\Program Files\Wireshark\tshark.exe
```

or:

```text
C:\Program Files (x86)\Wireshark\tshark.exe
```

## First-time setup

Download or clone this repository, then run:

```text
setup.bat
```

This will:

- create a local `.venv`
- upgrade pip
- install the Python dependencies from `requirements.txt`

You only need to run setup again if the dependencies change.

## Collect one match

Run:

```text
run.bat
```

The collector will:

1. wait for `StarSavior.exe`
2. automatically detect the active Windows network interface
3. start passive TShark capture
4. ask you to play **one ranked PvP match**
5. wait for you to press Enter after returning to Ranked
6. stop the capture
7. decode and enrich the match
8. write both a full debug JSON and a clean analytics JSON

Example:

```text
[collector] StarSavior detected.
[collector] Interface: Ethernet (TShark #1)
[collector] Starting passive capture: ...\captures\starsavior-pvp-....pcapng

CAPTURE IS RUNNING.
Play ONE ranked match normally.
Play through the result screen before stopping the capture.

When you are finished and back at Ranked, press Enter here to stop...
```

A successful decode will end with something similar to:

```text
[collector] Match decoded.
  Opponent:       ExamplePlayer [US]
  Opponent units: 4
  Opponent team:  Epindel (Wedding), Luna (Summer), Cristelle, Carnelia
  Opponent gear:  24
  Result:         WIN
  Raw capture:    ...\captures\starsavior-pvp-....pcapng
  Full JSON:      ...\matches\....json
  Clean JSON:     ...\matches\....-clean.json
```

### What to send

For normal PvP-data contribution, send only:

```text
matches\<match>-clean.json
```

You do not need to send the raw capture or the full debug JSON.

## Network interface detection

The collector tries to determine the active outbound Windows network interface automatically.

If automatic detection fails, it will display the available TShark interfaces and ask you to choose the correct numeric interface.

You can also override the interface manually:

```powershell
.\.venv\Scripts\python.exe .\collect.py --interface "Wi-Fi"
```

or:

```powershell
.\.venv\Scripts\python.exe .\collect.py --interface 3
```

To list all interfaces:

```powershell
.\.venv\Scripts\python.exe .\collect.py --list-interfaces
```

## Output folders

Generated files are kept out of Git.

```text
captures\
    Raw .pcapng captures

matches\
    Full decoded JSON
    Clean analytics JSON

research\
    Optional/manual decoder output
```

The repository `.gitignore` also excludes the local virtual environment, caches, captures, generated match files, reverse-engineering research, and game-bundle working directories.

## Manual decode

A saved PCAP can be decoded again without capturing another match:

```powershell
.\.venv\Scripts\python.exe .\decode_match.py `
    .\captures\your-capture.pcapng `
    -o .\research\match.json
```

To generate the clean analytics file from a full decoded JSON:

```powershell
.\.venv\Scripts\python.exe .\make_clean_match.py `
    .\research\match.json `
    -o .\research\match-clean.json
```

## Character and equipment enrichment

The decoder keeps raw protocol IDs/stat values while adding readable metadata.

Example character data:

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

Example equipment data:

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

Readable character lookups are cached in:

```text
lookups\units.json
```

Equipment/set metadata is stored in:

```text
equip-sets.json
```

## Game updates / compatibility

Some enrichment data depends on the installed StarSavior client.

The currently identified master-data bundles were verified against the **2026-09-01 client build**. A future game update may replace those bundles.

If this happens:

- packet decoding may continue to work
- existing cached lookups may continue to cover known units
- enrichment for new/changed content may require the lookup extraction logic to be updated

Keep raw captures from failed decodes so they can be tested again after the decoder is updated.

## Project status

This is an early tester build.

The current priority is reliable collection of:

- opponent/team composition
- character progression
- equipment/build data
- Potential records
- match result

The battle-event decoder is retained but is not currently the main focus.

If a capture fails, keep the `.pcapng` file and send the console error/output to the project maintainer.
