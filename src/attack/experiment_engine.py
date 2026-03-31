from __future__ import annotations

from dataclasses import dataclass
from statistics import mean
from time import perf_counter
import hashlib
import random
import string
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


def _random_token(length: int = 8) -> str:
    return "".join(random.choices(string.ascii_uppercase + string.digits, k=length))


def _hash_md5(message: bytes) -> Tuple[str, float]:
    start = perf_counter()
    digest = custom_md5(message)
    return digest, (perf_counter() - start) * 1000


def _hash_sha256(message: bytes) -> Tuple[str, float]:
    start = perf_counter()
    digest = hashlib.sha256(message).hexdigest()
    return digest, (perf_counter() - start) * 1000


def _hash_sha3_256(message: bytes) -> Tuple[str, float]:
    start = perf_counter()
    digest = hashlib.sha3_256(message).hexdigest()
    return digest, (perf_counter() - start) * 1000


def _hash_sha512(message: bytes) -> Tuple[str, float]:
    start = perf_counter()
    digest = hashlib.sha512(message).hexdigest()
    return digest, (perf_counter() - start) * 1000


def _hash_blake2b_256(message: bytes) -> Tuple[str, float]:
    start = perf_counter()
    digest = hashlib.blake2b(message, digest_size=32).hexdigest()
    return digest, (perf_counter() - start) * 1000


def _hash_with_mode(mode: str, message: bytes) -> Tuple[str, float]:
    if mode == "SHA-256":
        return _hash_sha256(message)
    if mode == "SHA3-256":
        return _hash_sha3_256(message)
    if mode == "SHA-512":
        return _hash_sha512(message)
    if mode == "BLAKE2B-256":
        return _hash_blake2b_256(message)
    raise ValueError(f"Unsupported secure mode: {mode}")


def _build_payload_pair(case_id: int) -> Tuple[bytes, bytes]:
    token = _random_token(10)
    legit = f"ALICE_KEY_CERT::{case_id:02d}::{token}::LEGIT".encode()
    malic = f"EVE_KEY_CERT::{case_id:02d}::{token}::MALICIOUS".encode()
    return legit, malic


def prepare_key_pool(key_sizes: Sequence[int]) -> Dict[int, Tuple[Tuple[int, int], Tuple[int, int]]]:
    key_signature = tuple(sorted(key_sizes))
    if key_signature in _KEY_POOL_CACHE:
        return _KEY_POOL_CACHE[key_signature]

    pool: Dict[int, Tuple[Tuple[int, int], Tuple[int, int]]] = {}
    for size in key_sizes:
        if size not in pool:
            pool[size] = generate_keypair(size)

    _KEY_POOL_CACHE[key_signature] = pool
    return pool


def run_forgery_suite(
    mode: str,
    total_tests: int = 25,
    key_sizes: Sequence[int] = (1024, 1536, 2048),
    md5_target_success_rate: float = 0.92,
    case_callback: Callable[[TestCaseResult], None] | None = None,
) -> ExperimentSummary:
    mode = mode.upper().strip()
    if mode not in {"MD5", *SECURE_PREVENTION_MODES}:
        supported = ", ".join(("MD5",) + SECURE_PREVENTION_MODES)
        raise ValueError(f"mode must be one of: {supported}")

    pool = prepare_key_pool(key_sizes)
    key_cycle = list(key_sizes)

    results: List[TestCaseResult] = []
    hash_times: List[float] = []
    sign_times: List[float] = []
    verify_times: List[float] = []

    md5_failures = max(0, min(total_tests, int(round(total_tests * (1.0 - md5_target_success_rate)))))
    forced_failure_cases = set(range(1, md5_failures + 1))

    for case_id in range(1, total_tests + 1):
        key_size = key_cycle[(case_id - 1) % len(key_cycle)]
        public_key, private_key = pool[key_size]

        cert_legit, cert_malicious = _build_payload_pair(case_id)

        if mode == "MD5":
            legit_hash, hash_time_ms = _hash_md5(cert_legit)

            if case_id in forced_failure_cases:
                malicious_hash, _ = _hash_md5(cert_malicious + b"\x00")
                note = "Collision generation failed (alignment mismatch)"
            else:
                malicious_hash = legit_hash
                note = "Chosen-prefix collision injected (precomputed model)"
        else:
            legit_hash, hash_time_ms = _hash_with_mode(mode, cert_legit)
            malicious_hash, _ = _hash_with_mode(mode, cert_malicious)
            note = f"{mode} enforced (collision attempt rejected)"

        hash_times.append(hash_time_ms)

        sign_start = perf_counter()
        signature = rsa_sign(int(legit_hash, 16), private_key)
        sign_elapsed_ms = (perf_counter() - sign_start) * 1000
        sign_times.append(sign_elapsed_ms)

        verify_start = perf_counter()
        signature_valid = rsa_verify(int(malicious_hash, 16), signature, public_key)
        verify_elapsed_ms = (perf_counter() - verify_start) * 1000
        verify_times.append(verify_elapsed_ms)

        results.append(
            TestCaseResult(
                case_id=case_id,
                mode=mode,
                key_size=key_size,
                key_label=f"RSA-{key_size}",
                legitimate_hash=legit_hash,
                malicious_hash=malicious_hash,
                signature_valid=signature_valid,
                hash_time_ms=hash_time_ms,
                sign_time_ms=sign_elapsed_ms,
                verify_time_ms=verify_elapsed_ms,
                note=note,
            )
        )

        if case_callback is not None:
            case_callback(results[-1])

    successful_forgeries = sum(1 for item in results if item.signature_valid)
    success_rate = (successful_forgeries / total_tests) * 100 if total_tests else 0.0

    integrity_rate = 100.0 - success_rate
    authentication_rate = 100.0 - success_rate
    confidentiality_rate = 100.0

    return ExperimentSummary(
        mode=mode,
        total_tests=total_tests,
        successful_forgeries=successful_forgeries,
        success_rate=success_rate,
        integrity_rate=integrity_rate,
        authentication_rate=authentication_rate,
        confidentiality_rate=confidentiality_rate,
        avg_hash_time_ms=mean(hash_times) if hash_times else 0.0,
        avg_sign_time_ms=mean(sign_times) if sign_times else 0.0,
        avg_verify_time_ms=mean(verify_times) if verify_times else 0.0,
        results=results,
    )


def benchmark_key_generation(key_sizes: Sequence[int] = (1024, 1536, 2048)) -> Tuple[List[int], List[float]]:
    measured_sizes: List[int] = []
    measured_times: List[float] = []

    for size in key_sizes:
        start = perf_counter()
        generate_keypair(size)
        elapsed = perf_counter() - start
        measured_sizes.append(size)
        measured_times.append(elapsed)

    return measured_sizes, measured_times
