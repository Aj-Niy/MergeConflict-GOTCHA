import pytest
from app.auth.security import verify_password, get_password_hash, create_access_token, decode_token

def test_password_hashing():
    pw = "supersecret123"
    hashed = get_password_hash(pw)
    assert verify_password(pw, hashed) is True
    assert verify_password("wrongpassword", hashed) is False

def test_jwt_token_encode_decode():
    sub = "user-12345"
    token = create_access_token(sub)
    payload = decode_token(token)
    assert payload is not None
    assert payload["sub"] == sub
