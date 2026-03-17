"""Manage secrets with Secret Manager: create, add version, access, delete."""

from google.cloud import secretmanager


def create_secret(project_id: str, secret_id: str):
    client = secretmanager.SecretManagerServiceClient()
    parent = f"projects/{project_id}"
    secret = client.create_secret(
        request={
            "parent": parent,
            "secret_id": secret_id,
            "secret": {"replication": {"automatic": {}}},
        }
    )
    print(f"Created secret: {secret.name}")
    return secret


def add_secret_version(project_id: str, secret_id: str, payload: str):
    client = secretmanager.SecretManagerServiceClient()
    parent = f"projects/{project_id}/secrets/{secret_id}"
    version = client.add_secret_version(
        request={"parent": parent, "payload": {"data": payload.encode("utf-8")}}
    )
    print(f"Added version: {version.name}")
    return version


def access_secret(project_id: str, secret_id: str, version_id: str = "latest") -> str:
    client = secretmanager.SecretManagerServiceClient()
    name = f"projects/{project_id}/secrets/{secret_id}/versions/{version_id}"
    response = client.access_secret_version(request={"name": name})
    payload = response.payload.data.decode("utf-8")
    print(f"Accessed secret version: {name}")
    return payload


def delete_secret(project_id: str, secret_id: str):
    client = secretmanager.SecretManagerServiceClient()
    name = f"projects/{project_id}/secrets/{secret_id}"
    client.delete_secret(request={"name": name})
    print(f"Deleted secret: {name}")
