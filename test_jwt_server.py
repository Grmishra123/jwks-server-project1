import pytest
from fastapi.testclient import TestClient
from datetime import datetime, timezone, timedelta
from jose import jwt
from jwt_server import app, generate_rsa_key, keys, clean_up_expired_keys

client = TestClient(app)

# Tests function to verify RSA key generation is successful and key is stored
def test_key_generation():
    kid = generate_rsa_key()  # Generate a new RSA key
    assert kid in keys  # Check if the generated key ID is in the keys dictionary

# Tests function to check the JWKS endpoint for correct response and format
def test_jwks():
    response = client.get("/jwks")  # Request JWKS from the server
    assert response.status_code == 200  # Ensure the HTTP response is 200 OK
    assert "keys" in response.json()  # Ensure the response has a 'keys' field

# Tests function to verify that the authentication endpoint issues a token
def test_auth():
    response = client.post("/auth")  # Post a request to the authentication endpoint
    assert response.status_code == 200  # Check for a 200 OK response
    assert "token" in response.json()  # Verify that a 'token' is included in the response

# Tests function to validate behavior with an expired token
def test_auth_expired():
    response = client.post("/auth?expired=true")  # Request an expired token for testing
    assert response.status_code == 200  # Ensure the HTTP response is 200 OK
    assert "token" in response.json()  # Verify the presence of a 'token' in the response
    token = response.json()["token"]  # Extract the token from the response

    # Gets JWKS to decode the JWT correctly
    jwks_response = client.get("/jwks").json()  # Get the JSON Web Key Set
    public_key_pem = None  # Initialize public key variable
    for key in jwks_response["keys"]:
        if key["kid"] == response.json()["token"]["kid"]:
            public_key_pem = key["n"]  # Assign the public key if the key ID matches
            break

    # Decodes the token using the public key
    decoded = jwt.decode(token, public_key_pem, algorithms=["RS256"], options={"verify_exp": True})
    # Check if the token is indeed expired
    assert decoded["exp"] < datetime.now(timezone.utc).timestamp()

# Tests function to ensure proper handling of invalid HTTP methods
def test_invalid_http_methods():
    assert client.post("/jwks").status_code == 405  # POST method should be disallowed for /jwks
    assert client.get("/auth").status_code == 405  # GET method should be disallowed for /auth

# Tests function to handle errors when no keys are available
def test_no_keys_error():
    keys.clear()  # Clear all keys to simulate no keys condition
    response = client.post("/auth")  # Attempt to authenticate
    assert response.status_code == 500  # Server should return an error
    assert response.json()["detail"] == "No keys available"  # Error message should be specific

# Tests to ensure expired keys are not included in JWKS response
def test_expired_key_not_in_jwks():
    kid = generate_rsa_key()  # Generate a new key
    keys[kid]['expiry'] = datetime.now(timezone.utc) - timedelta(hours=1)  # Set the key to be expired
    clean_up_expired_keys()  # Clean up the expired keys
    jwks_response = client.get("/jwks").json()  # Get the JWKS after cleanup
    assert kid not in [key["kid"] for key in jwks_response["keys"]]  # Verify the expired key is not listed
