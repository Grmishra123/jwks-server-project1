from fastapi import FastAPI, HTTPException, Query, status
from datetime import datetime, timedelta, timezone
from typing import Dict
from jose import jwt
import base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import uuid

app = FastAPI()

# Dictionary to store RSA keys along with their expiration metadata
keys: Dict[str, Dict] = {}
KEY_EXPIRY_HOURS = 1  # Sets the expiry time for each key to 1 hour

def generate_rsa_key():
    """
    Generates an RSA key pair for JWT signing, each with a unique key ID (kid) and an expiration time.
    The private key is used to sign the JWT, and the public key is exposed via the JWKS endpoint for validation.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    kid = str(uuid.uuid4())  # Generates a unique identifier for the key
    expiry = datetime.now(timezone.utc) + timedelta(hours=KEY_EXPIRY_HOURS)

    # Converts private and public keys to PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Stores the key with its metadata in the global dictionary
    keys[kid] = {
        "private": private_pem.decode(),
        "public": public_pem.decode(),
        "expiry": expiry
    }
    return kid

def get_jwks():
    """
    Retrieves all non-expired JSON Web Keys (JWKs) for JWT validation.
    This function filters out expired keys before returning the valid JWKs.
    """
    clean_up_expired_keys()  # Removes expired keys first
    jwks_keys = []
    for kid, key_info in keys.items():
        public_key = serialization.load_pem_public_key(key_info["public"].encode())
        public_numbers = public_key.public_numbers()
        # Encodes the modulus and exponent of the RSA key to Base64URL for JWK format
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
    """
    Removes keys that have expired from the global dictionary to prevent their use in token generation.
    """
    current_time = datetime.now(timezone.utc)
    expired_keys = [kid for kid, key_info in keys.items() if key_info["expiry"] <= current_time]
    for kid in expired_keys:
        del keys[kid]

@app.get("/jwks")
def jwks():
    """
    Endpoint to return the available JSON Web Keys.
    This allows clients to validate the JWTs signed by this server.
    """
    return get_jwks()

@app.post("/auth")
def auth(expired: bool = Query(False)):
    """
    Endpoint to generate a JWT. It can optionally create an expired JWT for testing purposes.
    """
    clean_up_expired_keys()
    
    if not keys:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="No keys available")

    key_id = next(iter(keys.keys()))  # Uses the first available key
    key_info = keys[key_id]

    # Sets token expiration based on the 'expired' query parameter
    expiry = key_info["expiry"] if not expired else datetime.now(timezone.utc) - timedelta(hours=1)

    token = jwt.encode(
        {"sub": "fake_user", "exp": expiry.timestamp()},
        key_info["private"],
        algorithm="RS256",
        headers={"kid": key_id}
    )
    
    return {"token": token}

# Generates the initial RSA key upon starting the server
generate_rsa_key()
