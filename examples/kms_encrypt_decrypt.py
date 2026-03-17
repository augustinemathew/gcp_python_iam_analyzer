"""Encrypt and decrypt data using Cloud KMS symmetric keys.

Creates a key ring and key, then encrypts and decrypts a plaintext message.
"""

from google.cloud import kms


def create_key_ring(project_id: str, location_id: str, key_ring_id: str):
    client = kms.KeyManagementServiceClient()
    location_name = client.common_location_path(project_id, location_id)
    key_ring = client.create_key_ring(
        request={"parent": location_name, "key_ring_id": key_ring_id, "key_ring": {}}
    )
    print(f"Created key ring: {key_ring.name}")
    return key_ring


def create_symmetric_key(project_id: str, location_id: str, key_ring_id: str, key_id: str):
    client = kms.KeyManagementServiceClient()
    key_ring_name = client.key_ring_path(project_id, location_id, key_ring_id)
    key = client.create_crypto_key(
        request={
            "parent": key_ring_name,
            "crypto_key_id": key_id,
            "crypto_key": {
                "purpose": kms.CryptoKey.CryptoKeyPurpose.ENCRYPT_DECRYPT,
            },
        }
    )
    print(f"Created key: {key.name}")
    return key


def encrypt(project_id: str, location_id: str, key_ring_id: str, key_id: str, plaintext: str):
    client = kms.KeyManagementServiceClient()
    key_name = client.crypto_key_path(project_id, location_id, key_ring_id, key_id)
    response = client.encrypt(
        request={"name": key_name, "plaintext": plaintext.encode("utf-8")}
    )
    print(f"Ciphertext length: {len(response.ciphertext)} bytes")
    return response.ciphertext


def decrypt(
    project_id: str,
    location_id: str,
    key_ring_id: str,
    key_id: str,
    ciphertext: bytes,
) -> str:
    client = kms.KeyManagementServiceClient()
    key_name = client.crypto_key_path(project_id, location_id, key_ring_id, key_id)
    response = client.decrypt(request={"name": key_name, "ciphertext": ciphertext})
    plaintext = response.plaintext.decode("utf-8")
    print(f"Decrypted: {plaintext}")
    return plaintext
