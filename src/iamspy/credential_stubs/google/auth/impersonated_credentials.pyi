from google.auth.credentials import Credentials as _BaseCredentials

class Credentials(_BaseCredentials):
    """Impersonated SA credential — identity: IMPERSONATED."""
    def __init__(
        self,
        source_credentials: _BaseCredentials,
        target_principal: str,
        target_scopes: list[str] | None = ...,
        delegates: list[str] | None = ...,
        lifetime: int = ...,
    ) -> None: ...

class IDTokenCredentials:
    def __init__(
        self,
        target_credentials: _BaseCredentials,
        target_audience: str | None = ...,
        include_email: bool = ...,
    ) -> None: ...
