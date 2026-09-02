#!/usr/bin/env python3
"""One-match passive collector wrapper for StarSavior PvP.

v0.5 workflow:
  1. Wait for StarSavior.exe.
  2. Start TShark/Npcap on the configured interface with a narrow TCP filter.
  3. User plays one ranked match.
  4. User presses Enter when finished.
  5. Stop TShark cleanly.
  6. Decode the PCAP with decode_match.py.
  7. Save full normalized JSON under matches/.
  8. Save analytics-ready clean JSON alongside it.

This version intentionally uses manual Enter-to-stop instead of trying to infer
match completion live. Raw PCAPNG is preserved by default.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

from decode_match import DecodeError, build_match, load_schema
from make_clean_match import make_clean


DEFAULT_TSHARK = Path(r"C:\Program Files\Wireshark\tshark.exe")
DEFAULT_INTERFACE = "auto"
DEFAULT_CAPTURE_FILTER = "tcp portrange 9300-9400"


def find_tshark(explicit: Optional[Path] = None) -> Path:
    candidates = []
    if explicit:
        candidates.append(explicit)

    which = shutil.which("tshark.exe") or shutil.which("tshark")
    if which:
        candidates.append(Path(which))

    candidates.extend(
        [
            DEFAULT_TSHARK,
            Path(r"C:\Program Files (x86)\Wireshark\tshark.exe"),
        ]
    )

    for path in candidates:
        if path and path.exists():
            return path

    raise RuntimeError(
        "TShark was not found. Install Wireshark or pass "
        '--tshark "C:\\path\\to\\tshark.exe".'
    )


def list_interfaces(tshark: Path) -> list[str]:
    proc = subprocess.run(
        [str(tshark), "-D"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"Could not list TShark interfaces (exit {proc.returncode}):\n"
            f"{proc.stderr.strip()}"
        )
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]



def get_active_local_ipv4() -> Optional[str]:
    """Return the IPv4 address Windows would use for normal outbound traffic."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # No packets need to be sent; connect() lets the OS choose a route.
            sock.connect(("1.1.1.1", 53))
            return sock.getsockname()[0]
        finally:
            sock.close()
    except OSError:
        return None


def get_windows_interface_alias(ipv4: str) -> Optional[str]:
    """Resolve a local IPv4 address to its Windows interface alias."""
    if os.name != "nt":
        return None

    escaped = ipv4.replace("'", "''")
    command = (
        "$x = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue "
        f"| Where-Object {{ $_.IPAddress -eq '{escaped}' }} "
        "| Select-Object -First 1 -ExpandProperty InterfaceAlias; "
        "if ($x) { $x }"
    )

    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", command],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except OSError:
        return None

    if proc.returncode != 0:
        return None

    alias = proc.stdout.strip()
    return alias or None


def choose_interface_interactively(lines: list[str]) -> tuple[str, str]:
    """Fallback when automatic interface detection is inconclusive."""
    print("[collector] Could not confidently detect the active network interface.")
    print("[collector] Available TShark interfaces:")
    for line in lines:
        print(f"  {line}")

    while True:
        choice = input("Enter the TShark interface number to use: ").strip()
        if not choice.isdigit():
            print("Please enter a numeric interface number.")
            continue

        for line in lines:
            m = re.match(r"^(\d+)\.\s+", line)
            if m and m.group(1) == choice:
                return choice, line

        print("That interface number was not found.")


def resolve_interface(lines: list[str], requested: str) -> tuple[str, str]:
    """Resolve --interface, using the active Windows route when set to auto."""
    requested = requested.strip()

    if requested.lower() != "auto":
        index = select_interface(lines, requested)
        return index, requested

    local_ip = get_active_local_ipv4()
    if local_ip:
        alias = get_windows_interface_alias(local_ip)
        if alias:
            try:
                index = select_interface(lines, alias)
                return index, alias
            except RuntimeError:
                pass

    return choose_interface_interactively(lines)

def select_interface(lines: list[str], requested: str) -> str:
    """Return a TShark interface selector.

    Numeric input is passed through. Otherwise match the friendly name shown
    by `tshark -D`, preferring an exact '(Name)' match.
    """
    requested = requested.strip()
    if requested.isdigit():
        return requested

    exact_suffix = f"({requested})".lower()
    exact = []
    partial = []

    for line in lines:
        low = line.lower()
        m = re.match(r"^(\d+)\.\s+", line)
        if not m:
            continue
        index = m.group(1)

        if low.endswith(exact_suffix):
            exact.append(index)
        elif requested.lower() in low:
            partial.append(index)

    matches = exact or partial
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        raise RuntimeError(
            f'Interface "{requested}" matched more than one TShark interface. '
            "Run with --list-interfaces and pass the numeric index."
        )

    available = "\n".join(f"  {line}" for line in lines)
    raise RuntimeError(
        f'Could not find TShark interface "{requested}".\n'
        "Available interfaces:\n"
        f"{available}"
    )


def starsavior_running() -> bool:
    if os.name != "nt":
        return True
    try:
        proc = subprocess.run(
            ["tasklist", "/FI", "IMAGENAME eq StarSavior.exe", "/NH"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        return "StarSavior.exe" in proc.stdout
    except OSError:
        return True


def wait_for_game() -> None:
    if starsavior_running():
        print("[collector] StarSavior detected.")
        return

    print("[collector] Waiting for StarSavior.exe ...")
    while not starsavior_running():
        time.sleep(1.0)
    print("[collector] StarSavior detected.")


def stop_tshark(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return

    # TShark should be given a console break so it flushes/finalizes the pcapng.
    try:
        if os.name == "nt" and hasattr(signal, "CTRL_BREAK_EVENT"):
            proc.send_signal(signal.CTRL_BREAK_EVENT)
        else:
            proc.send_signal(signal.SIGINT)
        proc.wait(timeout=10)
        return
    except Exception:
        pass

    try:
        proc.terminate()
        proc.wait(timeout=5)
        return
    except Exception:
        pass

    try:
        proc.kill()
    except Exception:
        pass


def safe_filename_part(value: object) -> str:
    text = str(value)
    text = re.sub(r"[^0-9A-Za-z._-]+", "_", text)
    return text.strip("._-") or "unknown"


def write_match_json(result: dict, match_dir: Path, started: dt.datetime) -> Path:
    match_dir.mkdir(parents=True, exist_ok=True)
    match_id = (result.get("match") or {}).get("match_id")

    stem = started.strftime("%Y-%m-%d_%H%M%S")
    if match_id is not None:
        stem += "_" + safe_filename_part(match_id)

    out = match_dir / f"{stem}.json"
    out.write_text(
        json.dumps(result, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return out


def write_clean_match_json(
    result: dict,
    full_json_path: Path,
) -> Path:
    clean_result = make_clean(result)
    clean_path = full_json_path.with_name(full_json_path.stem + "-clean.json")
    clean_path.write_text(
        json.dumps(clean_result, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return clean_path


def print_summary(
    result: dict,
    pcap_path: Path,
    json_path: Path,
    clean_json_path: Path,
) -> None:
    match = result.get("match") or {}
    opponent = result.get("opponent") or {}
    profile = opponent.get("profile") or {}
    units = opponent.get("units") or []
    events = result.get("battle_events") or []

    gear_count = sum(len(unit.get("equipment") or []) for unit in units)

    print()
    print("[collector] Match decoded.")
    print(f"  Opponent:       {profile.get('name') or '<unknown>'} "
          f"[{profile.get('region') or '?'}]")
    print(f"  Opponent units: {len(units)}")
    unit_names = [
        u.get("display_name") or u.get("name") or str(u.get("template_id"))
        for u in units
    ]
    if unit_names:
        print(f"  Opponent team:  {', '.join(unit_names)}")
    print(f"  Opponent gear:  {gear_count}")
    print(f"  Battle events:  {len(events)}")

    won = match.get("self_won")
    if won is True:
        print("  Result:         WIN")
    elif won is False:
        print("  Result:         LOSS")
    else:
        print("  Result:         <unknown>")

    print(f"  Raw capture:    {pcap_path}")
    print(f"  Full JSON:      {json_path}")
    print(f"  Clean JSON:     {clean_json_path}")

    warnings = ((result.get("capture") or {}).get("warnings") or [])
    failures = ((result.get("capture") or {}).get("decode_failures") or [])
    if warnings:
        print(f"  Capture warnings: {len(warnings)}")
    if failures:
        print(f"  Decode failures:  {len(failures)}")


def build_parser() -> argparse.ArgumentParser:
    here = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(
        description="Capture and decode one StarSavior ranked PvP match."
    )
    parser.add_argument(
        "--interface",
        default=DEFAULT_INTERFACE,
        help='TShark interface index/name, or "auto" (default: auto)',
    )
    parser.add_argument(
        "--capture-filter",
        default=DEFAULT_CAPTURE_FILTER,
        help=f'BPF capture filter (default: "{DEFAULT_CAPTURE_FILTER}")',
    )
    parser.add_argument(
        "--tshark",
        type=Path,
        help="Path to tshark.exe; normally auto-detected.",
    )
    parser.add_argument(
        "--schema",
        type=Path,
        default=here / "schema.json",
        help="schema.json path",
    )
    parser.add_argument(
        "--capture-dir",
        type=Path,
        default=here / "captures",
        help="directory for raw .pcapng files",
    )
    parser.add_argument(
        "--match-dir",
        type=Path,
        default=here / "matches",
        help="directory for normalized match JSON",
    )
    parser.add_argument(
        "--no-wait-for-game",
        action="store_true",
        help="start without waiting for StarSavior.exe",
    )
    parser.add_argument(
        "--delete-pcap",
        action="store_true",
        help="delete the raw PCAP after a successful decode",
    )
    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="print TShark interfaces and exit",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()

    try:
        tshark = find_tshark(args.tshark)
        interfaces = list_interfaces(tshark)

        if args.list_interfaces:
            print("\n".join(interfaces))
            return 0

        interface, interface_name = resolve_interface(interfaces, args.interface)

        if not args.no_wait_for_game:
            wait_for_game()

        args.capture_dir.mkdir(parents=True, exist_ok=True)
        started = dt.datetime.now()
        pcap_path = args.capture_dir / (
            "starsavior-pvp-" + started.strftime("%Y%m%d-%H%M%S") + ".pcapng"
        )

        cmd = [
            str(tshark),
            "-i",
            interface,
            "-f",
            args.capture_filter,
            "-B",
            "64",
            "-q",
            "-w",
            str(pcap_path),
        ]

        creationflags = 0
        if os.name == "nt":
            creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)

        print(f"[collector] Interface: {interface_name} (TShark #{interface})")
        print(f"[collector] Starting passive capture: {pcap_path}")
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            creationflags=creationflags,
        )

        # Give TShark a moment to initialize and catch immediate permission errors.
        time.sleep(1.0)
        if proc.poll() is not None:
            stderr = proc.stderr.read() if proc.stderr else ""
            raise RuntimeError(
                f"TShark exited immediately with code {proc.returncode}.\n"
                f"{stderr.strip()}"
            )

        print()
        print("CAPTURE IS RUNNING.")
        print("Play ONE ranked match normally.")
        print("Play through the result screen before stopping the capture.")
        print("Opening Battle Log is optional.")
        print()
        input("When you are finished and back at Ranked, press Enter here to stop... ")

        print("[collector] Stopping capture ...")
        stop_tshark(proc)

        if proc.stderr:
            # Read only after the process has ended so the pipe cannot block capture.
            stderr = proc.stderr.read().strip()
            if stderr and "Capturing on" not in stderr:
                print(f"[collector] TShark: {stderr}")

        if not pcap_path.exists() or pcap_path.stat().st_size == 0:
            raise RuntimeError("Capture file was not created or is empty.")

        print("[collector] Decoding capture ...")
        schema = load_schema(args.schema)
        result = build_match(pcap_path, schema)
        json_path = write_match_json(result, args.match_dir, started)
        clean_json_path = write_clean_match_json(result, json_path)

        print_summary(result, pcap_path, json_path, clean_json_path)

        if args.delete_pcap:
            pcap_path.unlink(missing_ok=True)
            print("[collector] Raw capture deleted (--delete-pcap).")

        return 0

    except KeyboardInterrupt:
        print("\n[collector] Cancelled.")
        return 130
    except (RuntimeError, DecodeError, OSError, ValueError) as exc:
        print(f"\nERROR: {exc}", file=sys.stderr)
        print(
            "If a capture was created, keep it; decode_match.py can be run "
            "against it manually for troubleshooting.",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
