"""Unit tests for bounty_guard.webhook_validator.

Covers:
- Valid signature accepted without raising.
- Missing / empty signature header raises SignatureError.
- Malformed prefix (sha1= instead of sha256=) raises SignatureError.
- Tampered payload raises SignatureError.
- Wrong secret raises SignatureError.
- compute_signature produces the correct format and value.
- verify_signature accepts bytes secret.
- Timing-safe comparison: different-length digest still raises SignatureError.
"""

from __future__ import annotations

import hashlib
import hmac

import pytest

from bounty_guard.webhook_validator import (
    SignatureError,
    compute_signature,
    verify_signature,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_signature(payload: bytes, secret: str) -> str:
    """Compute the expected sha256= signature for a payload."""
    mac = hmac.new(secret.encode("utf-8"), msg=payload, digestmod=hashlib.sha256)
    return f"sha256={mac.hexdigest()}"


SECRET = "super-secret-key"
PAYLOAD = b'{"action": "opened", "issue": {"number": 1}}'


# ---------------------------------------------------------------------------
# verify_signature tests
# ---------------------------------------------------------------------------


class TestVerifySignature:
    def test_valid_signature_does_not_raise(self):
        sig = _make_signature(PAYLOAD, SECRET)
        # Should complete without exception.
        verify_signature(payload=PAYLOAD, secret=SECRET, signature_header=sig)

    def test_valid_signature_with_bytes_secret(self):
        sig = _make_signature(PAYLOAD, SECRET)
        verify_signature(
            payload=PAYLOAD,
            secret=SECRET.encode("utf-8"),
            signature_header=sig,
        )

    def test_empty_signature_header_raises(self):
        with pytest.raises(SignatureError, match="Missing"):
            verify_signature(payload=PAYLOAD, secret=SECRET, signature_header="")

    def test_none_like_empty_string_raises(self):
        with pytest.raises(SignatureError):
            verify_signature(payload=PAYLOAD, secret=SECRET, signature_header="")

    def test_wrong_prefix_raises(self):
        # sha1= instead of sha256=
        bad_sig = "sha1=abc123"
        with pytest.raises(SignatureError, match="Invalid signature format"):
            verify_signature(payload=PAYLOAD, secret=SECRET, signature_header=bad_sig)

    def test_no_prefix_at_all_raises(self):
        mac = hmac.new(SECRET.encode(), msg=PAYLOAD, digestmod=hashlib.sha256)
        with pytest.raises(SignatureError, match="Invalid signature format"):
            verify_signature(
                payload=PAYLOAD, secret=SECRET, signature_header=mac.hexdigest()
            )

    def test_tampered_payload_raises(self):
        sig = _make_signature(PAYLOAD, SECRET)
        tampered = PAYLOAD + b" extra"
        with pytest.raises(SignatureError, match="does not match"):
            verify_signature(payload=tampered, secret=SECRET, signature_header=sig)

    def test_wrong_secret_raises(self):
        sig = _make_signature(PAYLOAD, "wrong-secret")
        with pytest.raises(SignatureError, match="does not match"):
            verify_signature(payload=PAYLOAD, secret=SECRET, signature_header=sig)

    def test_truncated_digest_raises(self):
        sig = _make_signature(PAYLOAD, SECRET)
        truncated = sig[:20]  # "sha256=" + first 13 hex chars
        with pytest.raises(SignatureError):
            verify_signature(
                payload=PAYLOAD, secret=SECRET, signature_header=truncated
            )

    def test_all_zeros_digest_raises(self):
        zero_sig = "sha256=" + "0" * 64
        with pytest.raises(SignatureError):
            verify_signature(
                payload=PAYLOAD, secret=SECRET, signature_header=zero_sig
            )

    def test_empty_payload_valid_signature(self):
        empty_payload = b""
        sig = _make_signature(empty_payload, SECRET)
        # Should not raise.
        verify_signature(payload=empty_payload, secret=SECRET, signature_header=sig)

    def test_unicode_payload_encoded_as_utf8(self):
        payload_str = '{"title": "\u0441\u0435\u043a\u044c\u044e\u0440\u0438\u0442\u0438"}'  # Russian
        payload_bytes = payload_str.encode("utf-8")
        sig = _make_signature(payload_bytes, SECRET)
        verify_signature(payload=payload_bytes, secret=SECRET, signature_header=sig)

    def test_signature_error_is_subclass_of_value_error(self):
        with pytest.raises(ValueError):
            verify_signature(payload=PAYLOAD, secret=SECRET, signature_header="")

    def test_signature_with_uppercase_hex_fails(self):
        """GitHub always uses lowercase hex; uppercase should not verify."""
        sig = _make_signature(PAYLOAD, SECRET)
        upper_sig = "sha256=" + sig[7:].upper()
        # hmac.compare_digest is case-sensitive for hex strings.
        with pytest.raises(SignatureError):
            verify_signature(
                payload=PAYLOAD, secret=SECRET, signature_header=upper_sig
            )


# ---------------------------------------------------------------------------
# compute_signature tests
# ---------------------------------------------------------------------------


class TestComputeSignature:
    def test_returns_sha256_prefix(self):
        sig = compute_signature(PAYLOAD, SECRET)
        assert sig.startswith("sha256=")

    def test_hex_digest_length(self):
        sig = compute_signature(PAYLOAD, SECRET)
        # sha256 produces 64 hex chars + 7 for "sha256=" prefix
        assert len(sig) == 64 + 7

    def test_matches_manual_computation(self):
        expected = _make_signature(PAYLOAD, SECRET)
        assert compute_signature(PAYLOAD, SECRET) == expected

    def test_bytes_secret_matches_string_secret(self):
        sig_str = compute_signature(PAYLOAD, SECRET)
        sig_bytes = compute_signature(PAYLOAD, SECRET.encode("utf-8"))
        assert sig_str == sig_bytes

    def test_empty_payload(self):
        sig = compute_signature(b"", SECRET)
        assert sig.startswith("sha256=")
        assert len(sig) == 71

    def test_different_secrets_produce_different_signatures(self):
        sig1 = compute_signature(PAYLOAD, "secret-one")
        sig2 = compute_signature(PAYLOAD, "secret-two")
        assert sig1 != sig2

    def test_different_payloads_produce_different_signatures(self):
        sig1 = compute_signature(b"payload-a", SECRET)
        sig2 = compute_signature(b"payload-b", SECRET)
        assert sig1 != sig2

    def test_roundtrip_verify(self):
        """Signature produced by compute_signature must pass verify_signature."""
        sig = compute_signature(PAYLOAD, SECRET)
        # Must not raise.
        verify_signature(payload=PAYLOAD, secret=SECRET, signature_header=sig)
