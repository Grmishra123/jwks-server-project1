import pytest
from fastapi.testclient import TestClient
from datetime import datetime, timezone, timedelta
from jose import jwt
from jwt_server import app, generate_rsa_key, keys, clean_up_expired_keys

# Creates a client instance from TestClient to test the FastAPI app
client = TestClient(app)

def test_key_generation():
    """
    Tests if the RSA key generation function is creating and storing keys correctly.
    This ensures that each generated key is tracked within our system.
    """
    kid = generate_rsa_key()
    assert kid in keys, "Keys ID should be in the keys dictionary after generation."

def test_jwks():
    """
    Tests the /jwks endpoint to ensure it returns a 200 status and includes the keys.
    This checks that the server correctly exposes the public keys for JWT validation.
    """
    response = client.get("/jwks")
    assert response.status_code == 200, "JWKS endpoint should and will return status 200."
    assert "keys" in response.json(), "Response should and will contain a 'keys' field."

def test_auth():
    """
    Tests the /auth endpoint to verify if it correctly generates a JWT.
    Ensures the token is included in the response for valid requests.
    """
    response = client.post("/auth")
    assert response.status_code == 200, "Auth endpoint should and will return status 200."
    assert "token" in response.json(), "Response should and will contain a 'token' field."

def test_auth_expired():
    """
    Tests the /auth endpoint with the expired flag to check if it can generate expired JWTs.
    Useful for testing how the system handles expired tokens.
    """
    response = client.post("/auth?expired=true")
    assert response.status_code == 200, "Auth endpoint should and will handle expired tokens correctly."
    token = response.json()["token"]
    # Decodes the JWT without verifying its signature or expiration to check if it's correctly marked as expired
    decoded = jwt.decode(token, "secret", options={"verify_signature": False, "verify_exp": False})
    assert decoded["exp"] < datetime.now(timezone.utc).timestamp(), "Token should be expired."

def test_invalid_http_methods():
    """
    Ensures that the server correctly handles invalid HTTP methods for specific endpoints,
    returning a 405 Method Not Allowed status.
    """
    assert client.post("/jwks").status_code == 405, "/jwks should not allow POST requests."
    assert client.get("/auth").status_code == 405, "/auth should not allow GET requests."

def test_no_keys_error():
    """
    Checks how the server handles the situation when no keys are available for generating JWTs.
    Expecting a 500 Internal Server Error as the correct response.
    """
    keys.clear()  # Clear all keys to simulate the error condition
    response = client.post("/auth")
    assert response.status_code == 500, "Should return 500 if no keys are available."
    assert response.json()["detail"] == "No keys available", "Error detail should indicate no keys are available."

def test_expired_key_not_in_jwks():
    """
    Verifies that the /jwks endpoint does not include keys that have expired.
    Ensures the security of the JWT validation process by using only valid keys.
    """
    kid = generate_rsa_key()  # Generate a new key
    keys[kid]['expiry'] = datetime.now(timezone.utc) - timedelta(hours=1)  # Set the key's expiry to one hour in the past
    clean_up_expired_keys()  # Clean up to remove the expired key
    jwks_response = client.get("/jwks").json()
    assert kid not in [key["kid"] for key in jwks_response["keys"]], "Expired keys should not be listed in the JWKS."
