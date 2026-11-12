#!/usr/bin/env python3
"""
Secure Automated File Organizer & Integrity Checker

Watches an intake folder, sorts files into category folders, and proves each
transfer was lossless by comparing SHA-256 hashes of source and destination.
Every transfer is written to an append-only, hash-chained JSONL manifest so
later edits to the log itself are detectable.

Usage:
    python secure_organizer.py watch  --watch ./incoming --dest ./organized
    python secure_organizer.py once   --watch ./incoming --dest ./organized
    python secure_organizer.py verify --dest ./organized
"""

import argparse
import hashlib
import json
import logging
import shutil
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------- config ----
CATEGORIES = {
    "cad_drawings": {".dwg", ".dxf", ".dgn"},
    "reports": {".pdf"},
    "documents": {".doc", ".docx", ".txt", ".rtf", ".odt"},
    "spreadsheets": {".xls", ".xlsx", ".csv"},
    "images": {".jpg", ".jpeg", ".png", ".tif", ".tiff"},
    "archives": {".zip", ".7z", ".tar", ".gz"},
}
FALLBACK_CATEGORY = "uncategorized"
IGNORED_SUFFIXES = {".tmp", ".part", ".crdownload", ".swp"}  # in-progress files
CHUNK_SIZE = 1024 * 1024  # 1 MiB; keeps memory flat for huge files
GENESIS_HASH = "0" * 64

log = logging.getLogger("organizer")


# --------------------------------------------------------------- hashing ----
def sha256_file(path: Path) -> str:
    """Stream a file through SHA-256 so large CAD files don't exhaust RAM."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# -------------------------------------------------------------- manifest ----
class Manifest:
    """Append-only JSONL log. Each entry embeds the hash of the previous one,
    so changing or deleting any past entry breaks the chain."""

    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.last_hash = self._load_last_hash()

    def _load_last_hash(self) -> str:
        last = GENESIS_HASH
        if self.path.exists():
            with open(self.path, encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        last = json.loads(line)["entry_hash"]
        return last

    def append(self, record: dict) -> None:
        record["prev_hash"] = self.last_hash
        record["entry_hash"] = sha256_text(json.dumps(record, sort_keys=True))
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, sort_keys=True) + "\n")
        self.last_hash = record["entry_hash"]

    def read_all(self) -> list[dict]:
        if not self.path.exists():
            return []
        with open(self.path, encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]

    def verify_chain(self) -> list[str]:
        """Return a list of problems found in the log itself."""
        problems, prev = [], GENESIS_HASH
        for i, entry in enumerate(self.read_all(), start=1):
            claimed = entry.pop("entry_hash", None)
            if entry.get("prev_hash") != prev:
                problems.append(f"entry {i}: chain broken (prev_hash mismatch)")
            if claimed != sha256_text(json.dumps(entry, sort_keys=True)):
                problems.append(f"entry {i}: entry contents were altered")
            prev = claimed
        return problems


#Core logic
def categorize(path: Path) -> str:
    ext = path.suffix.lower()
    for category, extensions in CATEGORIES.items():
        if ext in extensions:
            return category
    return FALLBACK_CATEGORY


def unique_path(target: Path) -> Path:
    """Never overwrite an existing file; add _1, _2... instead."""
    if not target.exists():
        return target
    n = 1
    while True:
        candidate = target.with_name(f"{target.stem}_{n}{target.suffix}")
        if not candidate.exists():
            return candidate
        n += 1


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def process_file(src: Path, dest_root: Path, quarantine: Path, manifest: Manifest) -> None:
    category = categorize(src)
    target_dir = dest_root / category
    target_dir.mkdir(parents=True, exist_ok=True)
    target = unique_path(target_dir / src.name)

    hash_before = sha256_file(src)
    shutil.copy2(src, target)  # copy first, delete source only after proof
    hash_after = sha256_file(target)
    hash_src_again = sha256_file(src)  # catches a file changing mid-transfer

    record = {
        "timestamp": now_iso(),
        "original_name": src.name,
        "category": category,
        "dest_path": str(target.relative_to(dest_root)),
        "size_bytes": target.stat().st_size,
        "sha256_source": hash_before,
        "sha256_dest": hash_after,
    }

    if hash_before == hash_after == hash_src_again:
        src.unlink()
        record["status"] = "VERIFIED"
        log.info("VERIFIED  %s -> %s", src.name, record["dest_path"])
    else:
        target.unlink(missing_ok=True)
        quarantine.mkdir(parents=True, exist_ok=True)
        shutil.move(str(src), str(unique_path(quarantine / src.name)))
        record["status"] = "MISMATCH_QUARANTINED"
        log.error("MISMATCH  %s (source moved to quarantine)", src.name)

    manifest.append(record)


def eligible(path: Path) -> bool:
    """Skip symlinks, dotfiles, directories, and in-progress downloads."""
    return (
        path.is_file()
        and not path.is_symlink()
        and not path.name.startswith(".")
        and path.suffix.lower() not in IGNORED_SUFFIXES
    )


def run_once(watch: Path, dest: Path, manifest: Manifest) -> int:
    count = 0
    for path in sorted(watch.iterdir()):
        if eligible(path):
            process_file(path, dest, dest / "_quarantine", manifest)
            count += 1
    return count


def run_watch(watch: Path, dest: Path, manifest: Manifest, interval: float) -> None:
    """Polling watcher (stdlib only). A file is processed only after its size
    and mtime stay unchanged for one full interval, so half-copied files are
    never touched. Swap in `watchdog` later for event-driven monitoring."""
    seen: dict[Path, tuple[int, float]] = {}
    log.info("Watching %s (every %.1fs). Ctrl+C to stop.", watch, interval)
    while True:
        for path in sorted(watch.iterdir()):
            if not eligible(path):
                continue
            st = path.stat()
            signature = (st.st_size, st.st_mtime)
            if seen.get(path) == signature:
                process_file(path, dest, dest / "_quarantine", manifest)
                seen.pop(path, None)
            else:
                seen[path] = signature
        time.sleep(interval)


def run_verify(dest: Path, manifest: Manifest) -> int:
    """Audit mode: check the log's chain, then re-hash every file on disk."""
    problems = manifest.verify_chain()
    checked = 0
    for entry in manifest.read_all():
        if entry.get("status") != "VERIFIED":
            continue
        path = dest / entry["dest_path"]
        checked += 1
        if not path.exists():
            problems.append(f"MISSING  {entry['dest_path']}")
        elif sha256_file(path) != entry["sha256_dest"]:
            problems.append(f"ALTERED  {entry['dest_path']} (hash differs from log)")

    if problems:
        print(f"INTEGRITY FAILURES ({len(problems)}):")
        for p in problems:
            print("  -", p)
        return 1
    print(f"OK: log chain intact, {checked} file(s) match their recorded SHA-256.")
    return 0


#CLI
def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("mode", choices=["watch", "once", "verify"])
    parser.add_argument("--watch", type=Path, help="intake folder to monitor")
    parser.add_argument("--dest", type=Path, required=True, help="organized output root")
    parser.add_argument("--interval", type=float, default=2.0, help="poll seconds (watch mode)")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    dest = args.dest.resolve()
    manifest = Manifest(dest / ".integrity" / "manifest.jsonl")

    if args.mode == "verify":
        return run_verify(dest, manifest)

    if not args.watch:
        parser.error("--watch is required for 'watch' and 'once'")
    watch = args.watch.resolve()
    if not watch.is_dir():
        parser.error(f"watch folder does not exist: {watch}")
    if watch == dest or dest in watch.parents or watch in dest.parents:
        parser.error("watch and dest folders must not overlap")
    dest.mkdir(parents=True, exist_ok=True)

    if args.mode == "once":
        print(f"Processed {run_once(watch, dest, manifest)} file(s).")
        return 0
    try:
        run_watch(watch, dest, manifest, args.interval)
    except KeyboardInterrupt:
        log.info("Stopped.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
