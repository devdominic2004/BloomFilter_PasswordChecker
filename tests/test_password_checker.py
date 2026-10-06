"""Tests for password_checker workflows and helper routines."""

import hashlib
from unittest.mock import patch

from bloom_filter import BloomFilter
from password_checker import (
    calculate_set_memory,
    format_bytes,
    menu_check_password,
    menu_statistics,
)


def test_format_bytes() -> None:
    assert format_bytes(500) == "500.00 B"
    assert format_bytes(1024) == "1.00 KB"
    assert format_bytes(1024 * 1024) == "1.00 MB"
    assert format_bytes(1024 * 1024 * 1024) == "1.00 GB"


def test_calculate_set_memory() -> None:
    test_set = {hashlib.sha1(f"item_{i}".encode()).hexdigest().upper() for i in range(100)}
    mem = calculate_set_memory(test_set)
    assert mem > 0
    # 100 items should take several kilobytes (table overhead + string objects)
    assert mem > 5000


def test_menu_check_password_compromised_and_safe(capsys) -> None:
    bf = BloomFilter(expected_items=100, false_positive_rate=0.01)
    compromised_pwd = "P@ssword123!"
    digest = hashlib.sha1(compromised_pwd.encode("utf-8")).hexdigest().upper()
    bf.add(digest)

    # Test compromised lookup
    with patch("getpass.getpass", return_value=compromised_pwd):
        menu_check_password(bf)
        captured = capsys.readouterr().out
        assert "COMPROMISED" in captured

    # Test safe lookup
    with patch("getpass.getpass", return_value="UnbreachedAndRandomPassphrase2026"):
        menu_check_password(bf)
        captured = capsys.readouterr().out
        assert "SAFE" in captured


def test_menu_statistics(capsys) -> None:
    bf = BloomFilter(expected_items=500, false_positive_rate=0.01)
    for i in range(100):
        bf.add(hashlib.sha1(f"test_item_{i}".encode()).hexdigest().upper())

    menu_statistics(bf)
    captured = capsys.readouterr().out
    assert "BLOOM FILTER STATISTICS" in captured
    assert "Items Inserted (n)" in captured
    assert "Theoretical FP Rate" in captured
    assert "Empirical Measured FP Rate" in captured
