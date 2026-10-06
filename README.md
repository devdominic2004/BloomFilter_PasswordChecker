# Compromised Password Detector (Bloom Filter)

An offline, privacy-first compromised password detector built in Python 3 using standard library modules (`hashlib`, `math`, `argparse`, `getpass`, `struct`, `secrets`) and tested with `pytest`.

It uses a space-efficient **Bloom filter** to screen passwords against millions of known breached credentials in microseconds, requiring over **99% less memory** than an in-memory hash set.

---

## Table of Contents
1. [Architecture & Zero-Storage Policy](#architecture--zero-storage-policy)
2. [Mathematical Foundations](#mathematical-foundations)
   - [Bit Array Sizing (m)](#1-bit-array-sizing-m)
   - [Optimal Hash Count (k)](#2-optimal-hash-count-k)
   - [Kirsch-Mitzenmacher Double Hashing](#3-kirsch-mitzenmacher-double-hashing)
   - [False-Positive Rate Estimations](#4-false-positive-rate-estimations)
3. [Acquiring a Public Wordlist](#acquiring-a-public-wordlist)
4. [Quickstart & Usage](#quickstart--usage)
   - [1. Build the Filter](#1-build-the-filter)
   - [2. Interactive CLI Checker](#2-interactive-cli-checker)
   - [3. Running the Test Suite](#3-running-the-test-suite)
5. [Benchmark & Memory Comparison](#benchmark--memory-comparison)
6. [Security Considerations & Limitations](#security-considerations--limitations)

---

## Architecture & Zero-Storage Policy

- **Zero-Storage Privacy**: Plaintext passwords are **never** logged, saved to disk, or stored in memory data structures. Lines from the wordlist or user inputs are immediately hashed into uppercase SHA-1 digests (conforming to standard breach databases like HaveIBeenPwned) and the original string references are discarded.
- **Offline & Self-Contained**: Operates with zero network calls and requires no third-party dependencies beyond `pytest` for the automated test suite.
- **Compact Custom Serialization**: Serialized using a 42-byte binary header (`BLMF` magic, version, $m$, $k$, item count, expected capacity, target FP rate) followed by the raw bytearray.

```
BloomFilter_BDA/
├── bloom_filter.py           # Core BloomFilter class and FP measurement logic
├── build_filter.py           # Wordlist parser (UTF-8/Latin-1 tolerant), SHA-1 hasher, binary builder
├── password_checker.py       # Interactive CLI (check, signup simulation, stats, benchmark)
├── tests/
│   ├── test_bloom_filter.py  # Unit & statistical tests for filter invariants
│   └── test_password_checker.py # CLI workflow and helper unit tests
└── README.md                 # Complete documentation
```

---

## Mathematical Foundations

A Bloom filter represents a set of $n$ elements using a bit array of size $m$ and $k$ independent hash functions.

### 1. Bit Array Sizing ($m$)
For an expected item capacity $n$ and target false-positive probability $p$ ($0 < p < 1$):

$$m = \left\lceil -\frac{n \cdot \ln(p)}{(\ln 2)^2} \right\rceil$$

**Derivation**:
The probability that a specific bit is not set to 1 by any of the $k$ hash functions for $n$ items is $(1 - 1/m)^{kn} \approx e^{-kn/m}$.
The probability that all $k$ bit probes for a non-member return 1 (a false positive) is:

$$p \approx \left(1 - e^{-kn/m}\right)^k$$

For fixed $m$ and $n$, $p$ is minimized when $e^{-kn/m} = 1/2$, which yields the optimal $k = \frac{m}{n} \ln 2$. Substituting this optimal $k$ back into the probability formula:

$$p = \left(1 - \frac{1}{2}\right)^k = 2^{-k} = 2^{-\frac{m}{n} \ln 2}$$

Taking the natural logarithm of both sides:

$$\ln(p) = -\frac{m}{n} (\ln 2)^2 \implies m = -\frac{n \cdot \ln(p)}{(\ln 2)^2}$$

*(For $p = 0.01$ (1%), $m \approx 9.585 \cdot n$ bits, or ~1.2 bytes per item).*

### 2. Optimal Hash Count ($k$)
Given $m$ bits and $n$ items, the optimal number of hash functions that minimizes false positives is:

$$k = \max\left(1, \operatorname{round}\left(\frac{m}{n} \cdot \ln 2\right)\right)$$

If $k$ is too small, insufficient bit signatures are generated, causing collisions. If $k$ is too large, bits saturate too quickly, degrading filter performance.

### 3. Kirsch-Mitzenmacher Double Hashing
Rather than calculating $k$ separate cryptographic hashes, we apply the **Kirsch-Mitzenmacher technique** to simulate $k$ independent hashes from a single 32-byte SHA-256 digest:

1. Compute $\text{digest} = \text{SHA-256}(\text{item})$ (32 bytes).
2. Slice into two 128-bit integers:
   - $h_1 = \operatorname{int}(\text{digest}[0:16])$
   - $h_2 = \operatorname{int}(\text{digest}[16:32])$
3. Guard $h_2$ against zero:
   $$h_2 = (h_2 \pmod{m - 1}) + 1$$
4. Compute the $i$-th bit position for $i \in \{0, 1, \dots, k-1\}$:
   $$g_i(x) = (h_1 + i \cdot h_2) \pmod m$$

This provides asymptotically identical performance to $k$ independent hash functions without the computational cost of multiple cryptographic passes.

### 4. False-Positive Rate Estimations
- **Theoretical Rate** (based on items inserted $n'$):
  $$p_{\text{theory}} = \left(1 - e^{-k \cdot n' / m}\right)^k$$
- **Empirical Bit-Density Estimate** (based on popcount $X$, the number of bits set to 1):
  $$p_{\text{est}} = \left(\frac{X}{m}\right)^k$$

---

## Acquiring a Public Wordlist

You can download a standard public password wordlist from the [SecLists](https://github.com/danielmiessler/SecLists) repository.

### Recommended Datasets:
- **Top 100,000 Passwords** (~782 KB):
  `https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/xato-net-10-million-passwords-100000.txt`
- **Top 1,000,000 Passwords** (~7.8 MB):
  `https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/xato-net-10-million-passwords-1000000.txt`

### Download Commands:

**PowerShell**:
```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/xato-net-10-million-passwords-100000.txt" -OutFile "passwords_100k.txt"
```

**curl (Linux / macOS / Git Bash)**:
```bash
curl -L -o passwords_100k.txt "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/xato-net-10-million-passwords-100000.txt"
```

---

## Quickstart & Usage

### 1. Build the Filter
Run `build_filter.py` with your wordlist file. The filter is sized automatically from the line count:

```bash
python build_filter.py --wordlist passwords_100k.txt --output passwords.bloom --fp-rate 0.01
```

*CLI Arguments:*
- `-w`, `--wordlist`: Path to plaintext wordlist (handles UTF-8 and Latin-1).
- `-o`, `--output`: Destination binary file path (default: `passwords.bloom`).
- `-p`, `--fp-rate`: Target false-positive probability (default: `0.01` i.e. 1%).

### 2. Interactive CLI Checker
Run `password_checker.py` to launch the interactive menu:

```bash
python password_checker.py --filter passwords.bloom --wordlist passwords_100k.txt
```

#### Menu Options:
1. **Check a password**: Secure masked input via `getpass`. Immediately hashed to SHA-1 before lookup. Plaintext is never displayed or stored.
2. **View filter statistics**: Displays items count, bit capacity, popcount saturation, theoretical FP rate, and runs an empirical false-positive test against 20,000 random nonces.
3. **Benchmark**: Compares the Bloom filter's memory footprint and average lookup latency against a Python `set` containing the same SHA-1 hashes.
4. **Exit**: Clean termination.

### 3. Running the Test Suite
The project includes a 31-test suite verifying zero false negatives, theoretical sizing, binary serialization, error handling, and interactive features:

```bash
python -m pytest tests/ -v
```

---

## Benchmark & Memory Comparison

Results obtained on a sample of **99,999 passwords** with a **1.00% target false-positive rate**:

| Metric | Bloom Filter | Python `set` of SHA-1 Hashes | Comparison / Tradeoff |
| :--- | :--- | :--- | :--- |
| **Total Memory** | **117.00 KB** | **11.72 MB** | **99.03% Memory Reduction** |
| **Memory per Item** | **~9.59 bits** (1.20 bytes) | **~122.9 bytes** | Bloom filter is **~102x more compact** |
| **Average Lookup Time** | **~4.5 µs** (220k queries/s) | **~0.12 µs** (8.2M queries/s) | Filter computes 1 SHA-256 + bit checks |
| **False Negatives** | **0.0000%** (Guaranteed) | **0.0000%** | Zero false negatives in both |
| **False Positives** | **1.0000%** (Measured on 20k probes) | **0.0000%** | Tradeoff: slight FP rate for 99% RAM savings |

---

## Security Considerations & Limitations

1. **No Deletion Supported**:
   Standard Bloom filters do not support deleting items. Once a bit is set to `1`, resetting it to `0` could erase bits shared by other hashed passwords, causing false negatives. If passwords must be deleted, a Counting Bloom Filter or Cuckoo Filter is required.
2. **False Positives are Probabilistic**:
   A Bloom filter may falsely report that a benign password is compromised (at rate $p \approx 1\%$). However, it **never produces false negatives**—a breached password present in the filter will never be reported as safe.
3. **NOT a Replacement for Argon2id / bcrypt / PBKDF2**:
   The Bloom filter is strictly an **in-memory breach screening index**. It does not replace cryptographic password storage:
   - When storing user passwords in your primary database, you **must** use a slow, memory-hard cryptographic hash (e.g. **Argon2id** or **bcrypt**) with a unique cryptographically secure salt.
   - The SHA-1 digests indexed in the Bloom filter are used purely for screening against public breach databases (such as HIBP) during registration or authentication.
