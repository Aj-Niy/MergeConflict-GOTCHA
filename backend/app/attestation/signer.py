import hashlib
import json
import base64
from typing import Dict, Any, Tuple
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from app.config import settings

# Global or generated keypair for the engine
_private_key: ed25519.Ed25519PrivateKey
_public_key: ed25519.Ed25519PublicKey

try:
    if settings.ATTESTATION_PRIVATE_KEY:
        raw_priv = base64.b64decode(settings.ATTESTATION_PRIVATE_KEY)
        _private_key = ed25519.Ed25519PrivateKey.from_private_bytes(raw_priv)
    else:
        _private_key = ed25519.Ed25519PrivateKey.generate()
except Exception:
    _private_key = ed25519.Ed25519PrivateKey.generate()

_public_key = _private_key.public_key()

def get_public_key_hex() -> str:
    raw_pub = _public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return raw_pub.hex()

def canonicalize_data(payload: Dict[str, Any]) -> bytes:
    """
    Produce deterministic canonical JSON (sorted keys, no extra whitespace).
    """
    return json.dumps(payload, sort_keys=True, separators=(',', ':')).encode('utf-8')

def compute_content_hash(payload: Dict[str, Any]) -> str:
    canonical_bytes = canonicalize_data(payload)
    return hashlib.sha256(canonical_bytes).hexdigest()

def create_signed_attestation(
    scan_id: str,
    repository_url: str,
    trust_score: float,
    risk_category: str,
    recommendation: str,
    capabilities: list,
    hidden_capabilities: list
) -> Tuple[str, str, str, Dict[str, Any]]:
    """
    Returns:
        (content_hash, signature_hex, public_key_hex, canonical_payload)
    """
    payload = {
        "scan_id": str(scan_id),
        "repository_url": str(repository_url),
        "trust_score": round(float(trust_score), 2),
        "risk_category": str(risk_category).upper(),
        "recommendation": str(recommendation),
        "capabilities": sorted([str(c) for c in capabilities]),
        "hidden_capabilities": sorted([str(h) for h in hidden_capabilities]),
        "issuer": "GOTCHA-Trust-Engine-v2",
        "engine_version": settings.VERSION
    }

    content_hash = compute_content_hash(payload)
    signature_bytes = _private_key.sign(content_hash.encode('utf-8'))
    signature_hex = signature_bytes.hex()
    pub_key_hex = get_public_key_hex()

    return content_hash, signature_hex, pub_key_hex, payload
