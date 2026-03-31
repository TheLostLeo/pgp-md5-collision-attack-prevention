from __future__ import annotations

from dataclasses import dataclass
from statistics import mean
from time import perf_counter
import hashlib
import os
from typing import Callable, Dict, List, Sequence, Tuple

from src.core.md5_core import custom_md5
from src.core.rsa_core import generate_keypair, rsa_sign, rsa_verify


_KEY_POOL_CACHE: Dict[Tuple[int, ...], Dict[int, Tuple[Tuple[int, int], Tuple[int, int]]]] = {}

SECURE_PREVENTION_MODES = ("SHA-256", "SHA3-256", "SHA-512", "BLAKE2B-256")


@dataclass
class TestCaseResult:
    case_id: int
    mode: str
    key_size: int
    key_label: str
    legitimate_hash: str
    malicious_hash: str
    signature_valid: bool
    hash_time_ms: float
    sign_time_ms: float
    verify_time_ms: float
    note: str


@dataclass
class ExperimentSummary:
    mode: str
    total_tests: int
    successful_forgeries: int
    success_rate: float
    integrity_rate: float
    authentication_rate: float
    confidentiality_rate: float
    avg_hash_time_ms: float
    avg_sign_time_ms: float
    avg_verify_time_ms: float
    results: List[TestCaseResult]


def _hash_md5(message: bytes) -> Tuple[str, float]:
    start = perf_counter()
    digest = custom_md5(message)
    return digest, (perf_counter() - start) * 1000


def _hash_with_mode(mode: str, message: bytes) -> Tuple[str, float]:
    start = perf_counter()

    if mode == "SHA-256":
        digest = hashlib.sha256(message).hexdigest()
    elif mode == "SHA3-256":
        digest = hashlib.sha3_256(message).hexdigest()
    elif mode == "SHA-512":
        digest = hashlib.sha512(message).hexdigest()
    elif mode == "BLAKE2B-256":
        digest = hashlib.blake2b(message, digest_size=32).hexdigest()
    else:
        raise ValueError("Unsupported mode")

    return digest, (perf_counter() - start) * 1000


def _build_payload_pair(case_id: int) -> Tuple[bytes, bytes]:
    collision_dir = "collisions"

    if case_id <= 23:
        file1 = os.path.join(collision_dir, f"msg{case_id}_A.bin")
        file2 = os.path.join(collision_dir, f"msg{case_id}_B.bin")

        if not os.path.exists(file1) or not os.path.exists(file2):
            legit = f"FALLBACK_{case_id}".encode()
            malic = f"FALLBACK_DIFF_{case_id}".encode()
            return legit, malic

        with open(file1, "rb") as f:
            legit = f.read()

        with open(file2, "rb") as f:
            malic = f.read()

        return legit, malic
    else:
        legit = f"LEGIT_CASE_{case_id}".encode()
        malic = f"MALICIOUS_CASE_{case_id}".encode()
        return legit, malic


def prepare_key_pool(key_sizes: Sequence[int]) -> Dict[int, Tuple[Tuple[int, int], Tuple[int, int]]]:
    key_signature = tuple(sorted(key_sizes))
    if key_signature in _KEY_POOL_CACHE:
        return _KEY_POOL_CACHE[key_signature]

    pool: Dict[int, Tuple[Tuple[int, int], Tuple[int, int]]] = {}
    for size in key_sizes:
        pool[size] = generate_keypair(size)

    _KEY_POOL_CACHE[key_signature] = pool
    return pool


def run_forgery_suite(
    mode: str,
    total_tests: int = 25,
    key_sizes: Sequence[int] = (1024, 1536, 2048),
    case_callback: Callable[[TestCaseResult], None] | None = None,
) -> ExperimentSummary:

    mode = mode.upper().strip()

    pool = prepare_key_pool(key_sizes)
    key_cycle = list(key_sizes)

    results: List[TestCaseResult] = []
    hash_times: List[float] = []
    sign_times: List[float] = []
    verify_times: List[float] = []

    for case_id in range(1, total_tests + 1):
        key_size = key_cycle[(case_id - 1) % len(key_cycle)]
        public_key, private_key = pool[key_size]

        cert_legit, cert_malicious = _build_payload_pair(case_id)

        if mode == "MD5":
            legit_hash, hash_time_ms = _hash_md5(cert_legit)
            malicious_hash, _ = _hash_md5(cert_malicious)

            if legit_hash == malicious_hash:
                note = "Real MD5 collision"
            else:
                note = "No collision"
        else:
            legit_hash, hash_time_ms = _hash_with_mode(mode, cert_legit)
            malicious_hash, _ = _hash_with_mode(mode, cert_malicious)
            note = f"{mode} secure"

        hash_times.append(hash_time_ms)

        sign_start = perf_counter()
        signature = rsa_sign(int(legit_hash, 16), private_key)
        sign_elapsed = (perf_counter() - sign_start) * 1000
        sign_times.append(sign_elapsed)

        verify_start = perf_counter()
        signature_valid = rsa_verify(int(malicious_hash, 16), signature, public_key)
        verify_elapsed = (perf_counter() - verify_start) * 1000
        verify_times.append(verify_elapsed)

        result = TestCaseResult(
            case_id,
            mode,
            key_size,
            f"RSA-{key_size}",
            legit_hash,
            malicious_hash,
            signature_valid,
            hash_time_ms,
            sign_elapsed,
            verify_elapsed,
            note,
        )

        results.append(result)

        if case_callback:
            case_callback(result)

    successful = sum(1 for r in results if r.signature_valid)
    success_rate = (successful / total_tests) * 100

    return ExperimentSummary(
        mode,
        total_tests,
        successful,
        success_rate,
        100 - success_rate,
        100 - success_rate,
        100,
        mean(hash_times),
        mean(sign_times),
        mean(verify_times),
        results,
    )


def benchmark_key_generation(key_sizes=(1024, 1536, 2048)):
    sizes = []
    times = []

    for size in key_sizes:
        start = perf_counter()
        generate_keypair(size)
        elapsed = perf_counter() - start

        sizes.append(size)
        times.append(elapsed)

    return sizes, times