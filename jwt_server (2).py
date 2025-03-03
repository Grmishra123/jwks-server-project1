from fastapi import FastAPI, HTTPException, Query, status
from datetime import datetime, timedelta, timezone
from typing import Dict
from jose import jwt
import base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import uuid

app = FastAPI()

keys: Dict[str, Dict] = {}  # Store RSA keys with their metadata
KEY_EXPIRY_HOURS = 1  # Key expiry time set to 1 hour

def generate_rsa_key():
    """Generates RSA keys for JWT signing with a unique key ID and expiry."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048  # Generates a 2048-bit RSA private key
    )
    public_key = private_key.public_key()  # Derives the public key from the private key
    kid = str(uuid.uuid4())  # Generates a unique key identifier
    expiry = datetime.now(timezone.utc) + timedelta(hours=KEY_EXPIRY_HOURS)  # Sets key expiry time

    # Serializes private and public keys to PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()  # No encryption for simplicity
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Stores keys with their ID, and expiry in the global dictionary
    keys[kid] = {
        "private": private_pem.decode(),
        "public": public_pem.decode(),
        "expiry": expiry
    }
    return kid  # Returns the unique identifier for the generated key

def get_jwks():
    """Retrieve non-expired JWKs for JWT validation."""
    clean_up_expired_keys()  # Removes expired keys before generating JWKS
    jwks_keys = []
    for kid, key_info in keys.items():
        public_key = serialization.load_pem_public_key(key_info["public"].encode())
        public_numbers = public_key.public_numbers()
        # Converts RSA modulus to a URL-safe base64 string
        n_bytes = public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, "big")

        jwks_keys.append({
            "kty": "RSA",
            "kid": kid,
            "alg": "RS256",
            "use": "sig",
            "n": base64.urlsafe_b64encode(n_bytes).rstrip(b"=").decode(),
            "e": "AQAB"
        })

    return {"keys": jwks_keys}

def clean_up_expired_keys():
    """Remove expired keys from the storage."""
    current_time = datetime.now(timezone.utc)
    expired_keys = [kid for kid, key_info in keys.items() if key_info["expiry"] <= current_time]
    for kid in expired_keys:
        del keys[kid]  # Deletes the key from the dictionary if it is expired

@app.get("/.well-known/jwks.json")
def jwks():
    """Endpoint to get JSON Web Keys."""
    return get_jwks()  # Returns the current set of JWKS

@app.post("/auth")
def auth(expired: bool = Query(False)):
    """Generate JWT with optional expired setting for testing."""
    clean_up_expired_keys()  # Removes expired keys first
    
    if not keys:
        # Raises HTTP 500 if no keys are available for signing the JWT
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="No keys available")

    key_id = next(iter(keys.keys()))  # Selects the first key available
    key_info = keys[key_id]

    # Adjusts the expiry for testing purposes if 'expired' query param is True
    expiry = key_info["expiry"] if not expired else datetime.now(timezone.utc) - timedelta(hours=1)

    token = jwt.encode(
        {"sub": "fake_user", "exp": expiry.timestamp()},
        key_info["private"],
        algorithm="RS256",
        headers={"kid": key_id}
    )
    
    return {"token": token}

# Generates initial key to ensure at least one key is available on startup
generate_rsa_key()
