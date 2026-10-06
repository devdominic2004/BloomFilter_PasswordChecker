"""Build a Bloom filter from a password wordlist.

Reads passwords line-by-line, computes their SHA-1 hex digests (uppercase),
inserts them into a Bloom filter sized from the wordlist line count,
and saves the filter to disk.

Strict security rule: Plaintext passwords are NEVER printed or logged.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
import time
from pathlib import Path
from typing import Iterator

from bloom_filter import BloomFilter


def count_non_empty_lines(file_path: Path) -> int:
    """Count non-empty lines in a file quickly using streaming binary reads."""
    count = 0
    with open(file_path, "rb") as f:
        for line in f:
            if line.rstrip(b"\r\n"):
                count += 1
    return count


def iter_passwords(file_path: Path) -> Iterator[str]:
    """Stream passwords from a file, tolerating UTF-8 and Latin-1 encodings.
    
    Trailing newline characters (\\r, \\n) are stripped. Passwords are never
    cached or stored globally; each string is yielded for immediate hashing.
    """
    with open(file_path, "rb") as f:
        for raw_line in f:
            clean_bytes = raw_line.rstrip(b"\r\n")
            if not clean_bytes:
                continue
            try:
                yield clean_bytes.decode("utf-8")
            except UnicodeDecodeError:
                # Fallback gracefully to Latin-1 which accepts all byte values 0x00-0xFF
                yield clean_bytes.decode("latin-1")


def hash_password_sha1(password: str) -> str:
    """Convert a password string into an uppercase SHA-1 hexadecimal digest.
    
    This matches standard breach database conventions (e.g. HaveIBeenPwned).
    """
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


def render_progress_bar(current: int, total: int, start_time: float, bar_width: int = 30) -> None:
    """Render a clean in-place terminal progress indicator."""
    elapsed = max(0.001, time.perf_counter() - start_time)
    rate = current / elapsed
    fraction = min(1.0, current / total) if total > 0 else 1.0
    filled = int(fraction * bar_width)
    bar = "=" * filled + (">" if filled < bar_width else "") + " " * (bar_width - filled - (1 if filled < bar_width else 0))
    percent = fraction * 100.0

    sys.stdout.write(
        f"\r[{bar}] {current:,}/{total:,} ({percent:5.1f}%) | {rate:,.0f} items/s | Elapsed: {elapsed:5.1f}s"
    )
    sys.stdout.flush()


def build_filter_from_file(
    wordlist_path: Path,
    output_path: Path,
    fp_rate: float,
    update_interval: int = 5000,
) -> BloomFilter:
    """Process the wordlist file and construct the Bloom filter.

    Args:
        wordlist_path: Path to the input password wordlist.
        output_path: Destination path for the serialized Bloom filter.
        fp_rate: Target false-positive probability.
        update_interval: How often to update the console progress display.

    Returns:
        The constructed BloomFilter instance.
    """
    if not wordlist_path.is_file():
        raise FileNotFoundError(f"Wordlist file not found: {wordlist_path}")

    print(f"[*] Analyzing wordlist: {wordlist_path}")
    total_lines = count_non_empty_lines(wordlist_path)
    if total_lines == 0:
        raise ValueError(f"Wordlist file is empty: {wordlist_path}")

    print(f"[*] Sizing Bloom filter for {total_lines:,} items with {fp_rate:.2%} target FP rate...")
    bf = BloomFilter(expected_items=total_lines, false_positive_rate=fp_rate)

    print(f"    - Bit array size (m): {bf.m:,} bits ({bf.memory_bytes / 1024:,.1f} KB)")
    print(f"    - Hash functions (k): {bf.k}")

    start_time = time.perf_counter()
    processed = 0

    print("[*] Processing passwords and populating filter...")
    for password in iter_passwords(wordlist_path):
        # Hash immediately to uppercase SHA-1 and discard raw password string
        digest = hash_password_sha1(password)
        bf.add(digest)
        processed += 1

        if processed % update_interval == 0 or processed == total_lines:
            render_progress_bar(processed, total_lines, start_time)

    sys.stdout.write("\n")
    sys.stdout.flush()

    total_time = max(0.001, time.perf_counter() - start_time)
    print(f"[+] Completed insertion in {total_time:.2f}s ({processed / total_time:,.0f} items/s)")

    # Serialize to disk
    output_path.parent.mkdir(parents=True, exist_ok=True)
    bf.save(output_path)
    file_size_kb = os.path.getsize(output_path) / 1024.0

    print(f"[+] Filter saved to: {output_path} ({file_size_kb:,.1f} KB on disk)")
    print(f"    - Items inserted: {bf.items_count:,}")
    print(f"    - Bits set to 1: {bf.popcount():,} / {bf.m:,} ({bf.popcount() / bf.m:.2%})")
    print(f"    - Theoretical FP rate: {bf.theoretical_false_positive_rate():.4%}")
    print(f"    - Bit-density estimated FP rate: {bf.estimated_false_positive_rate():.4%}")

    return bf


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Build a Bloom filter from a password wordlist for fast breach detection."
    )
    parser.add_argument(
        "-w",
        "--wordlist",
        type=Path,
        required=True,
        help="Path to the plaintext password wordlist file (one password per line).",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("passwords.bloom"),
        help="Path where the built Bloom filter binary will be saved (default: passwords.bloom).",
    )
    parser.add_argument(
        "-p",
        "--fp-rate",
        type=float,
        default=0.01,
        help="Target false-positive probability (default: 0.01 i.e. 1%%).",
    )
    return parser.parse_args()


def main() -> None:
    """Main CLI entrypoint."""
    args = parse_args()
    try:
        build_filter_from_file(
            wordlist_path=args.wordlist,
            output_path=args.output,
            fp_rate=args.fp_rate,
        )
    except Exception as exc:
        print(f"[-] Error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
