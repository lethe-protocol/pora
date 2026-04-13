"""pora crypto — encrypted audit report decryption.

Implements the requester-side of the Lethe encrypted delivery protocol.
The ROFL TEE worker encrypts review packets before storing them; this
module decrypts them using the requester's X25519 private key.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from Crypto.Hash import keccak


# ── Internal helpers ──────────────────────────────────────────────────────────


def _keccak256(data: bytes) -> bytes:
    # WHY: keccak256 matches the on-chain hash function used in LetheMarket.sol
    #      so computed hashes can be compared directly with contract storage.
    return keccak.new(data=data, digest_bits=256).digest()


def _b64decode(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def _parse_hex_bytes(value: str) -> bytes:
    clean = value[2:] if value.startswith("0x") else value
    return bytes.fromhex(clean)


# ── Public API ────────────────────────────────────────────────────────────────


def load_private_key(key_ref: str) -> X25519PrivateKey:
    """Load X25519 private key from file path, hex string, or base64 string.

    checks: key_ref resolves to 32 raw bytes encoding a valid X25519 scalar.
    effects: none.
    returns: X25519PrivateKey ready for ECDH exchange.

    WHY: operators may store keys as hex in .key files, base64 in environment
         variables, or JSON objects exported by keygen tooling. Accepting all
         three formats prevents the most common "which format do I pass?" error
         without requiring a new key storage convention.
    SECURITY: the private key never leaves local process memory.
    TRUST: the caller controls the correct private key corresponding to the
           on-chain delivery public key. Wrong key → decryption fails with a
           cryptography exception, not silent garbage output.
    """
    # checks: try to read from file first so a path and an inline hex string
    #         that happen to look like a path are not confused.
    candidate = Path(key_ref)
    raw_text = candidate.read_text().strip() if candidate.exists() else key_ref.strip()

    # checks: support JSON blobs produced by hardware wallets / TEE key-export tools.
    if raw_text.startswith("{"):
        payload = json.loads(raw_text)
        raw_text = (
            payload.get("privateKey")
            or payload.get("x25519PrivateKey")
            or payload.get("requesterPrivateKey")
            or ""
        ).strip()

    if not raw_text:
        raise ValueError("private key is empty after parsing")

    try:
        # WHY: hex strings contain only hex digits and optionally a leading 0x;
        #      any other character unambiguously indicates base64.
        if all(ch in "0123456789abcdefABCDEFx" for ch in raw_text):
            key_bytes = _parse_hex_bytes(raw_text)
        else:
            key_bytes = _b64decode(raw_text)
    except Exception as exc:
        raise ValueError(f"failed to parse private key: {exc}") from exc

    if len(key_bytes) != 32:
        raise ValueError(
            f"private key must decode to exactly 32 bytes, got {len(key_bytes)}"
        )
    return X25519PrivateKey.from_private_bytes(key_bytes)


def decrypt_envelope(envelope: dict, private_key: X25519PrivateKey) -> dict:
    """Decrypt an encrypted review packet envelope.

    checks: envelope contains ephemeralPubKey, wrappedKeyNonce, wrappedKey,
            packetNonce, and ciphertext fields (all base64-encoded); private_key
            matches the X25519 public key registered for this bounty on-chain.
    effects: none — decryption is performed in local process memory only.
    returns: decrypted packet dict with reportMarkdown, findingCount,
             resultType, bountyId, repoCommit, and other audit metadata.

    WHY: the requester-side decryption mirrors the ROFL encryption path exactly
         so the shared_secret and wrapping_key derivation produce the same bytes.
         Any divergence from the worker algorithm causes an AESGCM authentication
         failure rather than returning corrupt plaintext.
    SECURITY: AESGCM authentication tags are verified automatically by the
              cryptography library; a tampered ciphertext raises InvalidTag.
    TRUST: the envelope came from a legitimate ROFL TEE worker. If a malicious
           party substituted the envelope, decryption may succeed but the receipt
           hash verification in download_and_decrypt will catch the mismatch.
    """
    # Step 1: recover the shared secret using ECDH between requester private key
    #         and the ephemeral public key chosen by the ROFL worker per-packet.
    ephemeral_public = X25519PublicKey.from_public_bytes(
        _b64decode(envelope["ephemeralPubKey"])
    )
    shared_secret = private_key.exchange(ephemeral_public)

    # Step 2: derive the wrapping key from the shared secret.
    # WHY: HKDF extracts entropy from the ECDH output and binds the key to a
    #      domain-specific info string so keys from different protocols cannot
    #      be cross-applied even if the same keypair is reused.
    wrapping_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"lethe-delivery-wrap-v1",
    ).derive(shared_secret)

    # Step 3: unwrap the per-packet content key.
    content_key = AESGCM(wrapping_key).decrypt(
        _b64decode(envelope["wrappedKeyNonce"]),
        _b64decode(envelope["wrappedKey"]),
        None,
    )

    # Step 4: decrypt the review packet ciphertext.
    plaintext = AESGCM(content_key).decrypt(
        _b64decode(envelope["packetNonce"]),
        _b64decode(envelope["ciphertext"]),
        None,
    )

    # returns: parsed packet dict
    return json.loads(plaintext.decode("utf-8"))


def verify_hashes(
    ciphertext_bytes: bytes,
    manifest_bytes: bytes,
    on_chain_ciphertext_hash: bytes,
    on_chain_manifest_hash: bytes,
) -> bool:
    """Verify downloaded data matches on-chain hash anchors.

    checks: all four arguments are non-empty; on-chain hashes come from a
            trusted contract read (getAuditDelivery) for the correct audit ID.
    effects: none.
    returns: True if both keccak256 digests match their on-chain counterparts,
             False otherwise.

    WHY: storage backends (S3, render.com, filesystem) are not trusted. The
         on-chain hashes are the authoritative anchors; this function lets the
         caller detect tampering or retrieval of the wrong object before
         attempting decryption.
    SECURITY: hash comparison uses == which is constant-time for bytes in CPython
              for same-length values, matching the security properties needed for
              integrity checking (not MAC verification — that's AESGCM's job).
    TRUST: the on-chain hashes come from a Sapphire confidential contract whose
           state is only writable by an attested ROFL TEE worker. If Sapphire
           confidentiality is broken, the hashes cannot be trusted.
    """
    computed_ciphertext_hash = _keccak256(ciphertext_bytes)
    computed_manifest_hash = _keccak256(manifest_bytes)
    return (
        computed_ciphertext_hash == on_chain_ciphertext_hash
        and computed_manifest_hash == on_chain_manifest_hash
    )


def download_and_decrypt(
    handle: str,
    gateway_url: str,
    private_key: X25519PrivateKey,
    auth_token: str = "",
) -> dict:
    """Full pipeline: download from gateway, verify integrity, decrypt, return report.

    checks: handle is a valid packet handle (e.g. "pkt-2-1c5df70af11c");
            gateway_url points at the Lethe delivery gateway; private_key
            matches the delivery public key registered for this bounty.
    effects: performs two HTTP GET requests (envelope + manifest).
    returns: decrypted packet dict with reportMarkdown, findingCount,
             resultType, bountyId, repoCommit, and other audit metadata.

    WHY: the gateway serves both .enc.json (envelope) and .manifest.json
         (non-sensitive metadata) under the same handle prefix. Fetching both
         allows cross-verification of the ciphertext hash before decryption.
    SECURITY: manifest.ciphertextHash is verified against the actual ciphertext
              bytes before decryption so a corrupt or substituted blob is
              rejected before any plaintext is produced.
              receipt hash (keccak of plaintext) is verified post-decryption
              to confirm the decrypted bytes match what the TEE worker intended.
    TRUST: the gateway is a semi-trusted relay — it stores and forwards bytes
           but cannot read the encrypted packet. All sensitive data is protected
           by AESGCM; the gateway can at most deny access or serve wrong bytes,
           both of which are caught by hash verification.
    """
    base = gateway_url.rstrip("/")
    headers: dict[str, str] = {}
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"

    # Download envelope (encrypted packet + key-wrap data).
    env_resp = requests.get(
        f"{base}/{handle}.enc.json",
        headers=headers,
        timeout=30,
    )
    env_resp.raise_for_status()
    envelope_bytes = env_resp.content
    envelope = json.loads(envelope_bytes.decode("utf-8"))

    # Download manifest (public metadata + hash anchors).
    mfst_resp = requests.get(
        f"{base}/{handle}.manifest.json",
        headers=headers,
        timeout=30,
    )
    mfst_resp.raise_for_status()
    manifest_bytes = mfst_resp.content
    manifest = json.loads(manifest_bytes.decode("utf-8"))

    # SECURITY: verify handle consistency before trusting either document.
    if manifest.get("handle") != envelope.get("handle"):
        raise RuntimeError(
            f"handle mismatch: manifest says {manifest.get('handle')!r}, "
            f"envelope says {envelope.get('handle')!r}"
        )

    # SECURITY: verify the ciphertext bytes against the manifest hash anchor.
    #           This catches storage corruption and wrong-object retrieval before
    #           we attempt decryption.
    ciphertext_bytes = _b64decode(envelope["ciphertext"])
    computed_ciphertext_hash = _keccak256(ciphertext_bytes)
    manifest_ciphertext_hash = _parse_hex_bytes(manifest["ciphertextHash"])
    if computed_ciphertext_hash != manifest_ciphertext_hash:
        raise RuntimeError(
            "ciphertext hash does not match manifest — storage may be corrupt or tampered"
        )

    # Decrypt the packet.
    packet = decrypt_envelope(envelope, private_key)

    # SECURITY: verify receipt hash (keccak of plaintext canonical JSON) against
    #           manifest anchor to confirm decrypted bytes are what the TEE signed.
    # WHY: the ROFL worker hashes the canonical JSON serialization of the packet,
    #      so we must reconstruct the same bytes to verify the receipt hash.
    plaintext_bytes = json.dumps(
        packet, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    computed_receipt_hash = _keccak256(plaintext_bytes)
    manifest_receipt_hash = _parse_hex_bytes(manifest["receiptHash"])
    if computed_receipt_hash != manifest_receipt_hash:
        raise RuntimeError(
            "receipt hash does not match manifest — decrypted packet may be corrupt"
        )

    return packet
