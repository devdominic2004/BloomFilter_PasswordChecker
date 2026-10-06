"""Comprehensive pytest suite for the Bloom filter project.

Tests:
1. Invalid parameter validation (type and value bounds).
2. Sizing math correctness (m, k formulas).
3. Zero false negatives guarantee across all inserted items.
4. Measured false-positive rate within statistical margin of target.
5. Binary serialization round-trip (save/load) and corruption handling.
6. UTF-8 and Latin-1 wordlist encoding tolerance and pipeline verification.
"""

import hashlib
import math
import secrets
from pathlib import Path

import pytest

from bloom_filter import BloomFilter, measure_false_positive_rate
from build_filter import build_filter_from_file, count_non_empty_lines, hash_password_sha1


class TestBloomFilterParameters:
    """Test parameter validation and initialization invariants."""

    @pytest.mark.parametrize("invalid_n", [0, -1, -100])
    def test_invalid_expected_items_value(self, invalid_n: int) -> None:
        with pytest.raises(ValueError, match="positive integer > 0"):
            BloomFilter(expected_items=invalid_n, false_positive_rate=0.01)

    @pytest.mark.parametrize("invalid_n", ["1000", 100.5, None, True, False])
    def test_invalid_expected_items_type(self, invalid_n: object) -> None:
        with pytest.raises(TypeError, match="expected_items must be an integer"):
            BloomFilter(expected_items=invalid_n, false_positive_rate=0.01)  # type: ignore

    @pytest.mark.parametrize("invalid_p", [0.0, 1.0, -0.05, 1.5, -1.0])
    def test_invalid_false_positive_rate_value(self, invalid_p: float) -> None:
        with pytest.raises(ValueError, match="strictly between 0 and 1"):
            BloomFilter(expected_items=1000, false_positive_rate=invalid_p)

    @pytest.mark.parametrize("invalid_p", ["0.01", None, True, False])
    def test_invalid_false_positive_rate_type(self, invalid_p: object) -> None:
        with pytest.raises(TypeError, match="false_positive_rate must be a float"):
            BloomFilter(expected_items=1000, false_positive_rate=invalid_p)  # type: ignore


class TestBloomFilterMathAndSizing:
    """Test optimal sizing formulas and double-hashing invariants."""

    def test_optimal_sizing_formulas(self) -> None:
        n = 1000
        p = 0.01
        bf = BloomFilter(expected_items=n, false_positive_rate=p)

        # Expected m = ceil(-1000 * ln(0.01) / (ln(2)^2))
        expected_m = math.ceil(-n * math.log(p) / (math.log(2) ** 2))
        # Expected k = round((m / n) * ln(2))
        expected_k = round((expected_m / n) * math.log(2))

        assert bf.m == expected_m
        assert bf.m == 9586  # Precomputed value for n=1000, p=0.01
        assert bf.k == expected_k
        assert bf.k == 7

        # Bit array byte allocation: ceil(m / 8)
        assert len(bf._bitarray) == (expected_m + 7) // 8
        assert bf.memory_bytes == (expected_m + 7) // 8
        assert bf.memory_bytes() == (expected_m + 7) // 8

    def test_double_hashing_bounds_and_determinism(self) -> None:
        bf = BloomFilter(expected_items=500, false_positive_rate=0.01)
        item = "TEST_ITEM_VALUE"

        indexes_1 = bf._get_indexes(item)
        indexes_2 = bf._get_indexes(item)

        # Determinism
        assert indexes_1 == indexes_2
        assert len(indexes_1) == bf.k

        # Index bounds: 0 <= idx < m
        for idx in indexes_1:
            assert 0 <= idx < bf.m

        # Different items produce different index sets
        indexes_other = bf._get_indexes("ANOTHER_ITEM_VALUE")
        assert indexes_1 != indexes_other


class TestSetMembershipAndAccuracy:
    """Test zero false-negative guarantee and empirical false-positive rate."""

    def test_no_false_negatives(self) -> None:
        """Requirement: Zero false negatives across all inserted items."""
        n = 2500
        bf = BloomFilter(expected_items=n, false_positive_rate=0.01)

        inserted_items = [
            hashlib.sha1(f"password_sample_{i}_{secrets.token_hex(8)}".encode()).hexdigest().upper()
            for i in range(n)
        ]

        for item in inserted_items:
            bf.add(item)

        assert bf.items_count == n

        # Check that EVERY single inserted item returns True
        for item in inserted_items:
            assert bf.might_contain(item) is True, f"False negative encountered for item: {item}"
            assert (item in bf) is True

    def test_measured_false_positive_rate_within_margin(self) -> None:
        """Requirement: Measured FP rate within reasonable margin of target."""
        n = 5000
        target_p = 0.05  # 5% target
        bf = BloomFilter(expected_items=n, false_positive_rate=target_p)

        # Insert n items
        for i in range(n):
            digest = hashlib.sha1(f"known_breached_item_{i}".encode()).hexdigest().upper()
            bf.add(digest)

        # Test with 25,000 random non-member items
        num_trials = 25000
        fp_count, measured_rate = measure_false_positive_rate(
            bf, num_trials=num_trials, prefix="__EMPIRICAL_PROBE__"
        )

        # Theoretical rate should be ~0.05
        theo_rate = bf.theoretical_false_positive_rate()
        assert 0.045 <= theo_rate <= 0.055

        # With 25,000 trials at 5%, standard error SE = sqrt(0.05 * 0.95 / 25000) = 0.138%
        # 3.5-sigma bounds: [0.035, 0.065]
        assert 0.035 <= measured_rate <= 0.065, (
            f"Measured FP rate {measured_rate:.4%} out of expected range [3.5%, 6.5%] for target {target_p:.2%}"
        )


class TestPersistenceAndSerialization:
    """Test saving, loading, round-trip fidelity, and corruption handling."""

    def test_save_load_round_trip(self, tmp_path: Path) -> None:
        filepath = tmp_path / "test_filter.bloom"
        bf = BloomFilter(expected_items=1500, false_positive_rate=0.02)

        items = [
            hashlib.sha1(f"secret_{i}".encode()).hexdigest().upper()
            for i in range(500)
        ]
        for item in items:
            bf.add(item)

        bf.save(filepath)
        assert filepath.is_file()

        # Load back
        loaded = BloomFilter.load(filepath)

        # Verify all metadata attributes match
        assert loaded.expected_items == bf.expected_items
        assert loaded.false_positive_rate == pytest.approx(bf.false_positive_rate)
        assert loaded.m == bf.m
        assert loaded.k == bf.k
        assert loaded.items_count == bf.items_count
        assert loaded.memory_bytes == bf.memory_bytes
        assert loaded._bitarray == bf._bitarray

        # Verify membership queries behave identically
        for item in items:
            assert loaded.might_contain(item) is True

        # Non-members check
        for i in range(100):
            non_member = hashlib.sha1(f"definitely_absent_nonce_{i}".encode()).hexdigest().upper()
            assert loaded.might_contain(non_member) == bf.might_contain(non_member)

    def test_load_corrupted_files(self, tmp_path: Path) -> None:
        truncated_header = tmp_path / "truncated.bloom"
        truncated_header.write_bytes(b"BLMF\x00")
        with pytest.raises(ValueError, match="header truncated"):
            BloomFilter.load(truncated_header)

        bad_magic = tmp_path / "bad_magic.bloom"
        bad_magic.write_bytes(b"NOPE" + b"\x00" * 40)
        with pytest.raises(ValueError, match="magic bytes"):
            BloomFilter.load(bad_magic)

        bad_payload = tmp_path / "bad_payload.bloom"
        # Save a valid filter then truncate its payload
        valid_file = tmp_path / "valid.bloom"
        bf = BloomFilter(expected_items=100, false_positive_rate=0.01)
        bf.save(valid_file)
        raw = valid_file.read_bytes()
        bad_payload.write_bytes(raw[:-5])  # Cut off 5 bytes from payload
        with pytest.raises(ValueError, match="Corrupted filter payload"):
            BloomFilter.load(bad_payload)


class TestWordlistPipelineAndEncodings:
    """Test build_filter with mixed UTF-8 and Latin-1 wordlist contents."""

    def test_build_filter_with_diverse_encodings(self, tmp_path: Path) -> None:
        wordlist_path = tmp_path / "passwords.txt"
        output_filter_path = tmp_path / "passwords.bloom"

        # Create wordlist containing:
        # - Standard ASCII passwords
        # - UTF-8 multi-byte characters (emojis, accents)
        # - Latin-1 specific byte sequence
        # - Empty lines and CRLF / LF line endings
        content = (
            b"password123\r\n"
            b"admin\n"
            b"\n"  # Empty line to ignore
            b"caf\xc3\xa9\n"  # UTF-8 "café"
            b"\r\n"
            b"cr\xe8me\n"  # Latin-1 byte \xe8 (è) - invalid UTF-8 sequence alone
            b"Str0ng!P@ssw0rd\r\n"
        )
        wordlist_path.write_bytes(content)

        assert count_non_empty_lines(wordlist_path) == 5

        bf = build_filter_from_file(
            wordlist_path=wordlist_path,
            output_path=output_filter_path,
            fp_rate=0.01,
            update_interval=1,
        )

        assert bf.items_count == 5
        assert output_filter_path.is_file()

        # Check membership of all 5 passwords
        assert bf.might_contain(hash_password_sha1("password123")) is True
        assert bf.might_contain(hash_password_sha1("admin")) is True
        assert bf.might_contain(hash_password_sha1("café")) is True
        assert bf.might_contain(hash_password_sha1("crème")) is True
        assert bf.might_contain(hash_password_sha1("Str0ng!P@ssw0rd")) is True

        # Check an unbreached password
        safe_hash = hash_password_sha1("unbreached_unique_pw_987654321")
        assert bf.might_contain(safe_hash) is False
