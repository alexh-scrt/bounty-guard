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

    def test_large_payload_verifies_correctly(self):
        """A large payload should be handled without issues."""
        large_payload = b"x" * 1_000_000
        sig = _make_signature(large_payload, SECRET)
        # Should not raise.
        verify_signature(payload=large_payload, secret=SECRET, signature_header=sig)

    def test_large_payload_wrong_sig_raises(self):
        """A large payload with the wrong signature should fail."""
        large_payload = b"x" * 1_000_000
        sig = _make_signature(large_payload, "different-secret")
        with pytest.raises(SignatureError):
            verify_signature(payload=large_payload, secret=SECRET, signature_header=sig)

    def test_binary_payload_verifies_correctly(self):
        """Binary (non-UTF-8) payloads should be signed and verified correctly."""
        binary_payload = bytes(range(256))
        sig = _make_signature(binary_payload, SECRET)
        verify_signature(payload=binary_payload, secret=SECRET, signature_header=sig)

    def test_bytes_and_string_secret_produce_same_result(self):
        """String and bytes secrets should produce identical signatures."""
        sig_from_str = _make_signature(PAYLOAD, SECRET)
        # Verify both string and bytes secrets accept the same signature.
        verify_signature(payload=PAYLOAD, secret=SECRET, signature_header=sig_from_str)
        verify_signature(
            payload=PAYLOAD,
            secret=SECRET.encode("utf-8"),
            signature_header=sig_from_str,
        )

    def test_extra_whitespace_in_header_raises(self):
        """Whitespace around the signature value is not tolerated."""
        sig = _make_signature(PAYLOAD, SECRET)
        padded_sig = " " + sig
        with pytest.raises(SignatureError):
            verify_signature(
                payload=PAYLOAD, secret=SECRET, signature_header=padded_sig
            )

    def test_partial_prefix_raises(self):
        """A header that is just 'sha256' without '=' should raise."""
        with pytest.raises(SignatureError, match="Invalid signature format"):
            verify_signature(
                payload=PAYLOAD, secret=SECRET, signature_header="sha256"
            )

    def test_prefix_only_no_digest_raises(self):
        """A header that is 'sha256=' with no digest should fail verification."""
        with pytest.raises(SignatureError):
            verify_signature(
                payload=PAYLOAD, secret=SECRET, signature_header="sha256="
            )

    def test_multiple_calls_with_same_signature_all_pass(self):
        """Calling verify_signature multiple times with the same args should always pass."""
        sig = _make_signature(PAYLOAD, SECRET)
        for _ in range(5):
            verify_signature(payload=PAYLOAD, secret=SECRET, signature_header=sig)

    def test_different_payloads_different_signatures(self):
        """Signatures for different payloads should not be interchangeable."""
        payload_a = b"payload-a"
        payload_b = b"payload-b"
        sig_a = _make_signature(payload_a, SECRET)
        sig_b = _make_signature(payload_b, SECRET)
        # Cross-verification should fail.
        with pytest.raises(SignatureError):
            verify_signature(payload=payload_b, secret=SECRET, signature_header=sig_a)
        with pytest.raises(SignatureError):
            verify_signature(payload=payload_a, secret=SECRET, signature_header=sig_b)

    def test_secret_with_special_characters(self):
        """Secrets containing special characters should work correctly."""
        special_secret = "p@$$w0rd!#%^&*()-_=+[]{}|;':,.<>?/~`"
        sig = _make_signature(PAYLOAD, special_secret)
        verify_signature(
            payload=PAYLOAD, secret=special_secret, signature_header=sig
        )

    def test_secret_with_unicode_characters(self):
        """Secrets containing Unicode characters should work correctly."""
        unicode_secret = "\u00e9\u00e0\u00fc\u00f1\u4e2d\u6587"
        sig = _make_signature(PAYLOAD, unicode_secret)
        verify_signature(
            payload=PAYLOAD, secret=unicode_secret, signature_header=sig
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

    def test_digest_is_lowercase_hex(self):
        """The hex digest portion should be lowercase (GitHub convention)."""
        sig = compute_signature(PAYLOAD, SECRET)
        digest = sig[len("sha256="):]
        assert digest == digest.lower()
        # Verify it contains only hex characters.
        assert all(c in "0123456789abcdef" for c in digest)

    def test_deterministic_output(self):
        """Same inputs must always produce the same signature."""
        sig1 = compute_signature(PAYLOAD, SECRET)
        sig2 = compute_signature(PAYLOAD, SECRET)
        assert sig1 == sig2

    def test_large_payload_signature(self):
        """Signing a large payload should produce a standard-length signature."""
        large_payload = b"z" * 100_000
        sig = compute_signature(large_payload, SECRET)
        assert len(sig) == 71  # "sha256=" (7) + 64 hex chars

    def test_binary_payload_signature(self):
        """Binary payloads should produce valid signatures."""
        binary_payload = bytes(range(256))
        sig = compute_signature(binary_payload, SECRET)
        assert sig.startswith("sha256=")
        assert len(sig) == 71
        # Roundtrip verification.
        verify_signature(
            payload=binary_payload, secret=SECRET, signature_header=sig
        )

    def test_compute_and_verify_with_bytes_secret(self):
        """compute_signature with bytes secret should verify with the same bytes."""
        secret_bytes = SECRET.encode("utf-8")
        sig = compute_signature(PAYLOAD, secret_bytes)
        verify_signature(
            payload=PAYLOAD, secret=secret_bytes, signature_header=sig
        )

    def test_special_character_secret(self):
        """Secrets with special characters produce valid signatures."""
        special_secret = "s3cr3t!@#$%"
        sig = compute_signature(PAYLOAD, special_secret)
        verify_signature(
            payload=PAYLOAD, secret=special_secret, signature_header=sig
        )
