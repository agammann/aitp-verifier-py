"""Operation registry — maps a fixture ``input.operation`` to a verifier.

An operation absent from this table is one this implementation does not yet
support; the conformance runner reports SKIP for it (never a silent pass),
exactly as PLACEHOLDERS.md §"Operation key" requires.
"""

from __future__ import annotations

from typing import Any, Callable

from . import delegation, envelope, handshake, manifest, revocation, sessionbundle, tct, voucher

__all__ = ["OPERATIONS", "REQUIRED_ARGUMENTS", "supported"]

Verifier = Callable[..., dict[str, Any]]

OPERATIONS: dict[str, Verifier] = {
    "verify_envelope": envelope.verify_envelope,
    "verify_manifest": manifest.verify_manifest,
    "verify_tct": tct.verify_tct,
    "verify_tct_as_issuer": tct.verify_tct_as_issuer,
    "verify_attestation": tct.verify_attestation,
    "verify_grant_voucher": voucher.verify_grant_voucher,
    "verify_delegation_token": delegation.verify_delegation_token,
    "verify_revocation_snapshot": revocation.verify_revocation_snapshot,
    "verify_handshake_payload": handshake.verify_handshake_payload,
    "verify_session_bundle": sessionbundle.verify_session_bundle,
}

# Each tuple is a valid set of required top-level adapter arguments. Some
# operations accept different input shapes; the adapter must preserve those
# alternatives rather than reject a conformance fixture that takes one.
REQUIRED_ARGUMENTS: dict[str, tuple[tuple[str, ...], ...]] = {
    "verify_envelope": (("envelope",), ("active_tct", "requested_capability"),
                        ("manifest_fetch",), ("needed_key_for",)),
    "verify_manifest": (("manifest",),),
    "verify_tct": (("tct_token",),),
    "verify_tct_as_issuer": (("tct_token", "self_aid"),),
    "verify_attestation": (("tct_token", "expected_ext_key"),),
    "verify_grant_voucher": (("voucher_token",),),
    "verify_delegation_token": (("delegation_token",), ("delegation",)),
    "verify_revocation_snapshot": (("snapshot",),),
    "verify_handshake_payload": (("envelope",), ("peer_a", "peer_b")),
    "verify_session_bundle": (("self_aid", "session_bundle"),),
}


def supported(operation: str) -> bool:
    return operation in OPERATIONS
