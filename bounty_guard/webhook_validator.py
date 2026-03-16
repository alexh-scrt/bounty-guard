"""HMAC-SHA256 webhook signature verification for GitHub webhook payloads.

GitHub signs every webhook delivery with a shared secret using HMAC-SHA256
and includes the hex digest in the ``X-Hub-Signature-256`` header formatted
as ``sha256=<hex_digest>``.  This module provides a single public function,
:func:`verify_signature`, that validates the signature in a timing-safe manner.

Example usage::

    from bounty_guard.webhook_validator import verify_signature, SignatureError

    try:
        verify_signature(
            payload=request.body,
            secret=settings.github_webhook_secret,
            signature_header=request.headers.get("X-Hub-Signature-256", ""),
        )
    except SignatureError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
"""

from __future__ import annotations

import hashlib
import hmac
import logging

logger = logging.getLogger(__name__)

# The prefix GitHub always prepends to the hex digest.
_SIGNATURE_PREFIX = "sha256="


class SignatureError(ValueError):
    """Raised when a webhook signature is missing, malformed, or invalid.

    This is a subclass of :class:`ValueError` so callers that do not care
    about the distinction can catch the broader type.
    """


def verify_signature(
    payload: bytes,
    secret: str | bytes,
    signature_header: str,
) -> None:
    """Verify the HMAC-SHA256 signature of a GitHub webhook payload.

    Computes ``HMAC-SHA256(secret, payload)`` and compares it to the digest
    extracted from *signature_header* using a constant-time comparison to
    prevent timing-oracle attacks.

    Args:
        payload:          The raw request body bytes exactly as received from
                          GitHub (before any parsing or decoding).
        secret:           The shared webhook secret configured in the GitHub
                          App / repository webhook settings.  May be a plain
                          :class:`str` or :class:`bytes`; strings are encoded
                          as UTF-8.
        signature_header: The value of the ``X-Hub-Signature-256`` HTTP
                          header, e.g. ``"sha256=abc123..."``.

    Returns:
        None on success.

    Raises:
        SignatureError: If *signature_header* is empty or ``None``.
        SignatureError: If *signature_header* does not start with
                        ``"sha256="``.
        SignatureError: If the computed digest does not match the provided
                        digest (i.e. the payload has been tampered with or
                        the wrong secret is configured).
    """
    if not signature_header:
        raise SignatureError(
            "Missing X-Hub-Signature-256 header.  Ensure the webhook secret "
            "is configured in the GitHub App settings."
        )

    if not signature_header.startswith(_SIGNATURE_PREFIX):
        raise SignatureError(
            f"Invalid signature format: expected header to start with "
            f"{_SIGNATURE_PREFIX!r}, got {signature_header[:20]!r}."
        )

    provided_digest = signature_header[len(_SIGNATURE_PREFIX):]

    # Normalise secret to bytes.
    secret_bytes: bytes = secret.encode("utf-8") if isinstance(secret, str) else secret

    # Compute the expected HMAC-SHA256 digest.
    mac = hmac.new(secret_bytes, msg=payload, digestmod=hashlib.sha256)
    expected_digest = mac.hexdigest()

    # Use hmac.compare_digest for constant-time comparison.
    if not hmac.compare_digest(expected_digest, provided_digest):
        logger.warning(
            "Webhook signature verification failed.  "
            "Expected digest does not match provided digest."
        )
        raise SignatureError(
            "Webhook signature verification failed: the computed HMAC-SHA256 "
            "digest does not match the value in X-Hub-Signature-256.  "
            "Check that the correct webhook secret is configured."
        )

    logger.debug("Webhook signature verified successfully.")


def compute_signature(payload: bytes, secret: str | bytes) -> str:
    """Compute the GitHub-style HMAC-SHA256 signature for a payload.

    This is primarily a testing and tooling helper.  In production the
    signature is computed by GitHub and verified by :func:`verify_signature`.

    Args:
        payload: The raw payload bytes to sign.
        secret:  The shared webhook secret.  Strings are encoded as UTF-8.

    Returns:
        A string of the form ``"sha256=<hex_digest>"``.
    """
    secret_bytes: bytes = secret.encode("utf-8") if isinstance(secret, str) else secret
    mac = hmac.new(secret_bytes, msg=payload, digestmod=hashlib.sha256)
    return f"{_SIGNATURE_PREFIX}{mac.hexdigest()}"
