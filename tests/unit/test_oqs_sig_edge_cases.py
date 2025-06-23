# swaggerjacked with style and decomposed from https://github.com/open-quantum-safe/liboqs-python/blob/main/tests/test_sig.py
import oqs
import pytest

from .util.util import get_enabled_sigs


def test_not_supported() -> None:
    """
    Tests that the appropriate error is raised for an unsupported signature algorithm.
    """
    with pytest.raises(oqs.MechanismNotSupportedError):
        with oqs.Signature("unsupported_sig"):
            pass


def test_not_enabled() -> None:
    """
    Tests that the appropriate error is raised for a disabled signature algorithm.
    """
    supported_sigs = oqs.get_supported_sig_mechanisms()
    enabled_sigs = oqs.get_enabled_sig_mechanisms()
    disabled_sig = next(
        (sig for sig in supported_sigs if sig not in enabled_sigs), None
    )

    if disabled_sig:
        with pytest.raises(oqs.MechanismNotEnabledError):
            with oqs.Signature(disabled_sig):
                pass


def test_python_attributes() -> None:
    """
    Tests that the Python attributes of the Signature object are correctly set.
    """
    for alg_name in get_enabled_sigs():
        with oqs.Signature(alg_name) as sig:
            assert sig.method_name.decode() == alg_name
            assert sig.alg_version is not None
            assert 1 <= sig.claimed_nist_level <= 5
            assert sig.length_public_key > 0
            assert sig.length_secret_key > 0
            assert sig.length_signature > 0
