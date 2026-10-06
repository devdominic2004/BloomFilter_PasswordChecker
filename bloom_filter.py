"""Core Bloom Filter implementation for compromised password detection.

This module provides an offline, space-efficient probabilistic data structure
for set membership testing with zero false negatives and a bounded false-positive
rate, implemented using Python 3 standard library modules.
"""

from __future__ import annotations

import hashlib
import math
import os
import secrets
import struct
from typing import Union


class _CallableInt(int):
    """Integer subclass that can also be invoked as a zero-argument callable.
    
    This ensures API compatibility whether accessed as a property (`bf.memory_bytes`)
    or called as a method (`bf.memory_bytes()`).
    """

    def __call__(self) -> int:
        return int(self)


class BloomFilter:
    """A space-efficient probabilistic set membership filter.

    Formulas used:
    1. Optimal bit array size (m):
       m = ceil(-n * ln(p) / (ln(2)^2))
       Derivation: The false positive probability p with k hash functions is
       approximately p ≈ (1 - e^(-kn/m))^k. For a given m and n, the value of k
       that minimizes p is k = (m/n) * ln(2). Substituting this optimal k into
       the probability formula yields p = (1/2)^k = 2^(-(m/n) * ln(2)).
       Taking the natural log of both sides: ln(p) = -(m/n) * (ln 2)^2.
       Solving for m gives: m = -n * ln(p) / (ln 2)^2.

    2. Optimal number of hash functions (k):
       k = round((m / n) * ln(2))
       This balances the trade-off: too few hash functions don't generate enough
       bit signatures (higher collisions), while too many set too many bits to 1
       (saturating the filter prematurely).

    3. Kirsch-Mitzenmacher double hashing:
       g_i(x) = (h1(x) + i * h2(x)) % m, for i in 0 .. k-1
       Using a single cryptographic hash (SHA-256) sliced into two 128-bit
       integers (h1 and h2), this technique simulates k independent uniform
       hash functions without the computational overhead of computing k distinct
       hashes, with asymptotically negligible loss in false positive performance.

    4. Estimated false-positive rate from bit density:
       p_est = (X / m) ^ k
       where X is the number of bits set to 1 (popcount) in the filter.
       Because membership lookup inspects k bit positions, the probability that
       all k randomly chosen positions happen to already be set to 1 for a
       non-member is (X / m)^k.

    5. Theoretical false-positive rate:
       p_theory = (1 - e^(-k * n / m)) ^ k
       where n is the number of items actually inserted.
    """

    # Binary file header format:
    # 4s : Magic bytes (b"BLMF")
    # H  : Format version (uint16 = 1)
    # Q  : Bit array size m (uint64)
    # I  : Number of hash functions k (uint32)
    # Q  : Inserted items count (uint64)
    # Q  : Expected items count n (uint64)
    # d  : Target false positive rate p (float64)
    _HEADER_FORMAT = ">4sHQIQQd"
    _HEADER_SIZE = struct.calcsize(_HEADER_FORMAT)
    _MAGIC = b"BLMF"
    _VERSION = 1

    def __init__(self, expected_items: int, false_positive_rate: float) -> None:
        """Initialize a BloomFilter.

        Args:
            expected_items: The expected number of items (n > 0).
            false_positive_rate: Desired false-positive probability (0 < p < 1).

        Raises:
            TypeError: If parameter types are invalid.
            ValueError: If expected_items <= 0 or false_positive_rate not in (0, 1).
        """
        # Strict type checking (reject bool which is a subclass of int in Python)
        if isinstance(expected_items, bool) or not isinstance(expected_items, int):
            raise TypeError(f"expected_items must be an integer, got {type(expected_items).__name__}")
        if expected_items <= 0:
            raise ValueError(f"expected_items must be a positive integer > 0, got {expected_items}")

        if isinstance(false_positive_rate, bool) or not isinstance(false_positive_rate, (int, float)):
            raise TypeError(f"false_positive_rate must be a float, got {type(false_positive_rate).__name__}")
        if not (0.0 < false_positive_rate < 1.0):
            raise ValueError(f"false_positive_rate must be strictly between 0 and 1, got {false_positive_rate}")

        self.expected_items: int = expected_items
        self.false_positive_rate: float = float(false_positive_rate)

        # Formula 1: Sizing m (number of bits)
        # m = ceil(-n * ln(p) / (ln(2)^2))
        ln2_sq = math.log(2) ** 2
        self.m: int = math.ceil(-self.expected_items * math.log(self.false_positive_rate) / ln2_sq)

        # Formula 2: Hash count k
        # k = round((m / n) * ln(2))
        self.k: int = max(1, round((self.m / self.expected_items) * math.log(2)))

        # Allocate bytearray: ceil(m / 8) bytes
        byte_count = (self.m + 7) // 8
        self._bitarray: bytearray = bytearray(byte_count)
        self.items_count: int = 0

    def _get_indexes(self, item: Union[str, bytes]) -> list[int]:
        """Generate k bit indices for the item via Kirsch-Mitzenmacher double hashing.

        A single SHA-256 digest (32 bytes / 256 bits) is computed and split into
        two 128-bit integers: h1 (first 16 bytes) and h2 (last 16 bytes).
        Indices are calculated as: (h1 + i * h2) % m for i in 0 .. k-1.
        """
        if isinstance(item, str):
            data = item.encode("utf-8")
        elif isinstance(item, (bytes, bytearray)):
            data = bytes(item)
        else:
            raise TypeError(f"Item must be str or bytes, got {type(item).__name__}")

        # Compute single SHA-256 digest
        digest = hashlib.sha256(data).digest()

        # Split 256 bits into two 128-bit integers
        h1 = int.from_bytes(digest[:16], byteorder="big")
        h2 = int.from_bytes(digest[16:], byteorder="big")

        # Guard h2 against zero so step size is always positive
        if self.m > 1:
            h2 = (h2 % (self.m - 1)) + 1
        else:
            h2 = 1

        # Double hashing formula: (h1 + i * h2) % m
        m = self.m
        return [(h1 + i * h2) % m for i in range(self.k)]

    def add(self, item: Union[str, bytes]) -> None:
        """Add an item to the Bloom filter."""
        for idx in self._get_indexes(item):
            self._bitarray[idx >> 3] |= (1 << (idx & 7))
        self.items_count += 1

    def might_contain(self, item: Union[str, bytes]) -> bool:
        """Test membership of an item.

        Returns:
            False: The item is DEFINITELY NOT in the filter (no false negatives).
            True: The item MIGHT be in the filter (subject to false-positive rate).
        """
        for idx in self._get_indexes(item):
            if not (self._bitarray[idx >> 3] & (1 << (idx & 7))):
                return False
        return True

    def __contains__(self, item: Union[str, bytes]) -> bool:
        """Enable pythonic `item in bloom_filter` syntax."""
        return self.might_contain(item)

    @property
    def memory_bytes(self) -> _CallableInt:
        """Return the memory footprint of the underlying bit array in bytes."""
        return _CallableInt(len(self._bitarray))

    def estimated_false_positive_rate(self) -> float:
        """Calculate the estimated false-positive rate based on current bit saturation.

        Formula:
            p_est = (X / m) ^ k
        where X is the number of bits set to 1 (popcount) in the filter bit array.
        """
        if self.m == 0:
            return 0.0
        # Fast C-level popcount using int.bit_count() on little-endian bytes
        set_bits = int.from_bytes(self._bitarray, "little").bit_count()
        fraction_set = set_bits / self.m
        return fraction_set ** self.k

    def theoretical_false_positive_rate(self) -> float:
        """Calculate the theoretical false-positive rate based on inserted items count.

        Formula:
            p_theory = (1 - e^(-k * n / m)) ^ k
        """
        if self.m == 0 or self.items_count == 0:
            return 0.0
        exponent = -self.k * self.items_count / self.m
        return (1.0 - math.exp(exponent)) ** self.k

    def popcount(self) -> int:
        """Return the total number of bits currently set to 1."""
        return int.from_bytes(self._bitarray, "little").bit_count()

    def save(self, path: Union[str, os.PathLike]) -> None:
        """Serialize the Bloom filter and its metadata to a binary file.

        Args:
            path: Destination file path.
        """
        header = struct.pack(
            self._HEADER_FORMAT,
            self._MAGIC,
            self._VERSION,
            self.m,
            self.k,
            self.items_count,
            self.expected_items,
            self.false_positive_rate,
        )
        with open(path, "wb") as f:
            f.write(header)
            f.write(self._bitarray)

    @classmethod
    def load(cls, path: Union[str, os.PathLike]) -> BloomFilter:
        """Deserialize a Bloom filter from a binary file.

        Args:
            path: Source file path.

        Returns:
            A restored BloomFilter instance.

        Raises:
            FileNotFoundError: If the file does not exist.
            ValueError: If the file is corrupted, truncated, or has an invalid header.
        """
        with open(path, "rb") as f:
            header_bytes = f.read(cls._HEADER_SIZE)
            if len(header_bytes) < cls._HEADER_SIZE:
                raise ValueError("Corrupted filter file: header truncated.")

            magic, version, m, k, items_count, expected_items, fp_rate = struct.unpack(
                cls._HEADER_FORMAT, header_bytes
            )

            if magic != cls._MAGIC:
                raise ValueError(f"Invalid file format: magic bytes {magic!r} != {cls._MAGIC!r}")
            if version != cls._VERSION:
                raise ValueError(f"Unsupported filter version: {version}")

            expected_payload_bytes = (m + 7) // 8
            payload = f.read()
            if len(payload) != expected_payload_bytes:
                raise ValueError(
                    f"Corrupted filter payload: expected {expected_payload_bytes} bytes, "
                    f"found {len(payload)} bytes."
                )

        # Instantiate without calling __init__ to bypass recalculation
        instance = cls.__new__(cls)
        instance.expected_items = expected_items
        instance.false_positive_rate = fp_rate
        instance.m = m
        instance.k = k
        instance.items_count = items_count
        instance._bitarray = bytearray(payload)
        return instance


def measure_false_positive_rate(
    bloom_filter: BloomFilter,
    num_trials: int = 10000,
    prefix: str = "__NONCE_PROBE__",
) -> tuple[int, float]:
    """Measure the false-positive rate empirically using high-entropy random probes.

    Probes are generated with random nonces guaranteed not to exist in normal
    wordlists, hashed with SHA-1 hex uppercase (matching wordlist digests),
    and tested against the Bloom filter.

    Args:
        bloom_filter: The filter to evaluate.
        num_trials: Number of test queries to perform.
        prefix: Unique probe prefix to ensure items are non-members.

    Returns:
        tuple of (false_positive_count, measured_rate)
    """
    false_positives = 0
    for _ in range(num_trials):
        # Generate high-entropy probe string guaranteed not to be in any dictionary
        probe = f"{prefix}_{secrets.token_hex(20)}"
        probe_hash = hashlib.sha1(probe.encode("utf-8")).hexdigest().upper()
        if bloom_filter.might_contain(probe_hash):
            false_positives += 1

    rate = false_positives / num_trials if num_trials > 0 else 0.0
    return false_positives, rate
