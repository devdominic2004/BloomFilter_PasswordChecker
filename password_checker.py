"""Interactive CLI tool to check compromised passwords and test the Bloom filter.

Provides:
  a. Password lookup via secure input (getpass)
  b. Filter statistics (theoretical vs measured false-positive rate)
  c. Benchmark: Bloom filter vs Python set (memory footprint and lookup latency)
  d. Exit
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import math
import os
import secrets
import sys
import time
from pathlib import Path
from typing import Optional, Set

from bloom_filter import BloomFilter, measure_false_positive_rate
from build_filter import hash_password_sha1, iter_passwords


def format_bytes(num_bytes: int | float) -> str:
    """Format byte count into human-readable representation."""
    for unit in ("B", "KB", "MB", "GB"):
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:,.2f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:,.2f} TB"


def hash_input_securely(prompt: str) -> Optional[str]:
    """Prompt user for a password securely, immediately hash with SHA-1, and clear raw text."""
    try:
        raw_password = getpass.getpass(prompt)
    except (KeyboardInterrupt, EOFError):
        print("\n[!] Input cancelled.")
        return None

    if not raw_password:
        return ""

    # Hash immediately to uppercase SHA-1 digest
    digest = hash_password_sha1(raw_password)
    # Overwrite reference immediately to avoid lingering plaintext
    del raw_password
    return digest


def menu_check_password(bf: BloomFilter) -> None:
    """Option A: Check whether a password appears in the compromised database."""
    print("\n--- Check Password ---")
    digest = hash_input_securely("Enter password to test (input hidden): ")
    if digest is None:
        return
    if not digest:
        print("[-] Error: Empty password entered.")
        return

    # Check Bloom filter
    is_compromised = bf.might_contain(digest)
    est_fp = bf.estimated_false_positive_rate()

    if is_compromised:
        print("\n[!] COMPROMISED: Password was found in the breach database!")
        print(f"    - Probabilistic guarantee: Zero false negatives (compromised with high certainty).")
        print(f"    - Current false-positive probability: {est_fp:.4%}")
    else:
        print("\n[+] SAFE: Password was NOT found in the breach database.")
        print("    - Bloom filters guarantee 0% false negatives.")


def menu_statistics(bf: BloomFilter) -> None:
    """Option B: Display detailed filter metrics and measure empirical FP rate."""
    print("\n=======================================================")
    print("                 BLOOM FILTER STATISTICS               ")
    print("=======================================================")
    popcnt = bf.popcount()
    saturation = popcnt / bf.m if bf.m > 0 else 0.0
    theo_fp = bf.theoretical_false_positive_rate()
    est_fp = bf.estimated_false_positive_rate()

    print(f"Items Inserted (n)        : {bf.items_count:,}")
    print(f"Items Expected (capacity) : {bf.expected_items:,}")
    print(f"Bit Array Size (m)        : {bf.m:,} bits ({format_bytes(bf.memory_bytes)})")
    print(f"Hash Functions Count (k)  : {bf.k}")
    print(f"Bits Set to 1 (popcount)  : {popcnt:,} ({saturation:.2%} saturation)")
    print(f"Bits per Item (m/n)       : {bf.m / max(1, bf.items_count):.2f} bits")
    print(f"Target FP Rate            : {bf.false_positive_rate:.4%}")
    print(f"Theoretical FP Rate       : {theo_fp:.4%}")
    print(f"Bit-Density Est. FP Rate  : {est_fp:.4%}")

    print("\n--- Empirical False-Positive Rate Measurement ---")
    print("Testing with randomly generated nonces guaranteed not in wordlist...")
    trials = 20000
    t0 = time.perf_counter()
    fp_count, measured_fp = measure_false_positive_rate(bf, num_trials=trials)
    elapsed = max(0.001, time.perf_counter() - t0)

    print(f"Random Probes Tested      : {trials:,} in {elapsed:.2f}s ({trials / elapsed:,.0f} queries/s)")
    print(f"False Positives Detected  : {fp_count:,}")
    print(f"Empirical Measured FP Rate: {measured_fp:.4%}")

    delta = abs(measured_fp - theo_fp)
    print(f"Delta (Measured - Theory) : {delta:.4%} ({'+' if measured_fp >= theo_fp else '-'}{delta:.4%})")
    print("=======================================================")


def build_sample_set(
    wordlist_path: Optional[Path],
    max_items: int = 100000,
) -> Set[str]:
    """Load or generate a set of SHA-1 uppercase digests for benchmarking."""
    hash_set: Set[str] = set()

    if wordlist_path and wordlist_path.is_file():
        print(f"[*] Loading up to {max_items:,} hashes from wordlist: {wordlist_path}")
        for password in iter_passwords(wordlist_path):
            hash_set.add(hash_password_sha1(password))
            if len(hash_set) >= max_items:
                break
        return hash_set

    # Fallback to synthetic sample of high-entropy items
    print(f"[*] Generating {max_items:,} synthetic hashes for benchmark...")
    for i in range(max_items):
        digest = hashlib.sha1(f"benchmark_synthetic_password_{i}".encode()).hexdigest().upper()
        hash_set.add(digest)

    return hash_set


def calculate_set_memory(hash_set: Set[str]) -> int:
    """Calculate the full memory footprint of a Python set of strings in bytes."""
    # Internal hash table table overhead
    table_bytes = sys.getsizeof(hash_set)
    # Total memory of each individual string object
    elements_bytes = sum(sys.getsizeof(h) for h in hash_set)
    return table_bytes + elements_bytes


def menu_benchmark(bf: BloomFilter, default_wordlist: Optional[Path]) -> None:
    """Option C: Benchmark Bloom filter vs Python set (memory and lookup speed)."""
    print("\n=======================================================")
    print("            BENCHMARK: BLOOM FILTER vs PYTHON SET      ")
    print("=======================================================")

    wordlist_path = default_wordlist
    if not (wordlist_path and wordlist_path.is_file()):
        try:
            user_input = input("Enter wordlist path (or press Enter for synthetic sample): ").strip()
            if user_input:
                candidate = Path(user_input)
                if candidate.is_file():
                    wordlist_path = candidate
                else:
                    print(f"[-] '{candidate}' not found. Using synthetic sample.")
        except (KeyboardInterrupt, EOFError):
            return

    # Benchmark sample size
    target_count = min(max(10000, bf.items_count), 100000)
    hash_set = build_sample_set(wordlist_path, max_items=target_count)
    actual_items = len(hash_set)

    # 1. Memory comparison
    bf_bytes = int(bf.memory_bytes)
    # Scale Bloom filter bitarray proportionally to the benchmarked item count if needed
    if bf.items_count > 0:
        scaled_bf_bytes = int(bf_bytes * (actual_items / bf.items_count))
    else:
        scaled_bf_bytes = bf_bytes

    set_bytes = calculate_set_memory(hash_set)
    savings = (1.0 - (scaled_bf_bytes / set_bytes)) * 100.0

    print("\n--- 1. Memory Footprint ---")
    print(f"Items Evaluated       : {actual_items:,}")
    print(f"Bloom Filter Memory   : {format_bytes(scaled_bf_bytes)} ({scaled_bf_bytes * 8 / actual_items:.2f} bits/item)")
    print(f"Python Set Memory     : {format_bytes(set_bytes)} ({set_bytes / actual_items:.1f} bytes/item)")
    print(f"Memory Savings        : {savings:.2f}% reduction with Bloom filter")

    # 2. Lookup speed comparison
    print("\n--- 2. Lookup Latency Benchmark ---")
    query_count = 20000
    print(f"Generating {query_count:,} test queries (50% hits, 50% misses)...")

    # Mix 50% hits and 50% misses
    sample_list = list(hash_set)
    hits_sample = sample_list[: query_count // 2]
    misses_sample = [
        hashlib.sha1(f"benchmark_miss_{secrets.token_hex(16)}_{i}".encode()).hexdigest().upper()
        for i in range(query_count - len(hits_sample))
    ]
    queries = hits_sample + misses_sample

    # Test Bloom filter lookup speed
    t0 = time.perf_counter_ns()
    for q in queries:
        bf.might_contain(q)
    t1 = time.perf_counter_ns()
    bf_total_ns = t1 - t0
    bf_avg_us = (bf_total_ns / query_count) / 1000.0
    bf_qps = query_count / (bf_total_ns / 1e9)

    # Test Python set lookup speed
    t0 = time.perf_counter_ns()
    for q in queries:
        _ = q in hash_set
    t1 = time.perf_counter_ns()
    set_total_ns = t1 - t0
    set_avg_us = (set_total_ns / query_count) / 1000.0
    set_qps = query_count / (set_total_ns / 1e9)

    print(f"Bloom Filter Avg Time : {bf_avg_us:.3f} us/lookup ({bf_qps:,.0f} queries/sec)")
    print(f"Python Set Avg Time   : {set_avg_us:.3f} us/lookup ({set_qps:,.0f} queries/sec)")

    print("\n--- Architectural Trade-off Summary ---")
    print("  * Bloom Filter: Drastically lower memory (~10 bits/item vs ~80-100 bytes/item).")
    print("    Ideal for massive breach lists in memory-constrained environments or high-concurrency caches.")
    print("  * Python Set  : Exact membership with 0% false positives, but requires ~70x-100x more RAM.")
    print("=======================================================")


def print_banner(bf: BloomFilter, filter_path: Path) -> None:
    """Print the interactive application banner."""
    print("=======================================================")
    print("     COMPROMISED PASSWORD DETECTOR (BLOOM FILTER)     ")
    print("=======================================================")
    print(f"Filter File    : {filter_path}")
    print(f"Loaded Items   : {bf.items_count:,} / {bf.expected_items:,} capacity")
    print(f"Bit Array Size : {bf.m:,} bits ({format_bytes(bf.memory_bytes)})")
    print(f"Hash Count     : k = {bf.k} | Target FP Rate: {bf.false_positive_rate:.2%}")
    print("=======================================================")


def main_menu(bf: BloomFilter, filter_path: Path, wordlist_path: Optional[Path]) -> None:
    """Run the interactive CLI menu loop."""
    print_banner(bf, filter_path)

    menu_prompt = """
Select an action:
  a / 1. Check a password
  b / 2. View filter statistics (theoretical vs measured FP rate)
  c / 3. Benchmark: Bloom filter vs Python set
  d / 4. Exit

Choice: """

    while True:
        try:
            choice = input(menu_prompt).strip().lower()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting. Goodbye!")
            sys.exit(0)

        if choice in ("a", "1"):
            menu_check_password(bf)
        elif choice in ("b", "2"):
            menu_statistics(bf)
        elif choice in ("c", "3"):
            menu_benchmark(bf, wordlist_path)
        elif choice in ("d", "4", "exit", "quit", "q"):
            print("Exiting. Goodbye!")
            sys.exit(0)
        else:
            print("[-] Invalid selection. Please enter a, b, c, or d.")


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Interactive password breach checker and Bloom filter tester."
    )
    parser.add_argument(
        "-f",
        "--filter",
        type=Path,
        default=Path("passwords.bloom"),
        help="Path to the saved Bloom filter binary file (default: passwords.bloom).",
    )
    parser.add_argument(
        "-w",
        "--wordlist",
        type=Path,
        default=None,
        help="Optional path to original wordlist for benchmark comparisons.",
    )
    return parser.parse_args()


def main() -> None:
    """CLI entrypoint."""
    args = parse_args()

    if not args.filter.is_file():
        print(f"[-] Error: Bloom filter file not found at '{args.filter}'.", file=sys.stderr)
        print("[*] Please build the filter first using build_filter.py, for example:", file=sys.stderr)
        print(f"    python build_filter.py --wordlist path/to/wordlist.txt --output {args.filter}", file=sys.stderr)
        sys.exit(1)

    try:
        bf = BloomFilter.load(args.filter)
    except Exception as exc:
        print(f"[-] Error loading Bloom filter: {exc}", file=sys.stderr)
        sys.exit(1)

    main_menu(bf, args.filter, args.wordlist)


if __name__ == "__main__":
    main()
