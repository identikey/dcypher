# swaggerjacked with style and decomposed from https://github.com/open-quantum-safe/liboqs-python/blob/main/tests/test_kem.py
import platform
from typing import List

import oqs


def get_enabled_kems() -> List[str]:
    """
    Returns a list of enabled KEMs, filtered to exclude disabled algorithms.
    """
    disabled_kem_patterns = []
    if platform.system() == "Windows":
        disabled_kem_patterns.append(
            ""
        )  # Add any Windows-specific disabled patterns here

    enabled_kems = oqs.get_enabled_kem_mechanisms()

    return [
        alg_name
        for alg_name in enabled_kems
        if not any(item in alg_name for item in disabled_kem_patterns)
    ]


def get_enabled_sigs() -> List[str]:
    """
    Returns a list of enabled signature algorithms, filtered to exclude disabled algorithms.
    """
    disabled_sig_patterns = []
    if platform.system() == "Windows":
        disabled_sig_patterns.append(
            ""
        )  # Add any Windows-specific disabled patterns here

    enabled_sigs = oqs.get_enabled_sig_mechanisms()

    return [
        alg_name
        for alg_name in enabled_sigs
        if not any(item in alg_name for item in disabled_sig_patterns)
    ]


def get_sigs_with_ctx_support() -> List[str]:
    """
    Returns a list of enabled signature algorithms that support context strings.
    """
    return [
        alg_name
        for alg_name in get_enabled_sigs()
        if oqs.Signature(alg_name).details["sig_with_ctx_support"]
    ]
