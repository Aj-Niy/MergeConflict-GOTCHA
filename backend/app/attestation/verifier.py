import hashlib
from typing import Dict, Any, Tuple
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature
from app.attestation.signer import canonicalize_data, compute_content_hash

def verify_attestation(
    payload: Dict[str, Any],
    content_hash: str,
    signature_hex: str,
    public_key_hex: str
) -> Tuple[bool, str, str]:
    """
    Verifies the canonical content hash and Ed25519 signature.
    Returns:
        (is_valid: bool, recomputed_hash: str, status_message: str)
    """
    recomputed = compute_content_hash(payload)
    if recomputed != content_hash:
        return False, recomputed, f"Hash mismatch: stored hash {content_hash} != recomputed {recomputed}"

    try:
        pub_bytes = bytes.fromhex(public_key_hex)
        sig_bytes = bytes.fromhex(signature_hex)
        pub_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
        pub_key.verify(sig_bytes, content_hash.encode('utf-8'))
        return True, recomputed, "Cryptographic attestation signature verified successfully against published public key."
    except InvalidSignature:
        return False, recomputed, "Invalid Ed25519 cryptographic signature."
    except Exception as e:
        return False, recomputed, f"Verification failed with error: {str(e)}"
