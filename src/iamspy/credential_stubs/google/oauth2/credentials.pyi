from google.auth.credentials import Credentials as _BaseCredentials

class Credentials(_BaseCredentials):
    """OAuth user credential — identity: USER (delegated)."""
    def __init__(
        self,
        token: str | None = ...,
        refresh_token: str | None = ...,
        id_token: str | None = ...,
        token_uri: str | None = ...,
        client_id: str | None = ...,
        client_secret: str | None = ...,
        scopes: list[str] | None = ...,
        **kwargs: object,
    ) -> None: ...
    @classmethod
    def from_authorized_user_file(
        cls, filename: str, scopes: list[str] | None = ...,
    ) -> "Credentials": ...
    @classmethod
    def from_authorized_user_info(
        cls, info: dict, scopes: list[str] | None = ...,
    ) -> "Credentials": ...
    def refresh(self, request: object) -> None: ...
    @property
    def valid(self) -> bool: ...
    @property
    def expired(self) -> bool: ...
    @property
    def refresh_token(self) -> str | None: ...
