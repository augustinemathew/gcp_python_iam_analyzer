from google.auth.credentials import Credentials as _BaseCredentials

class Credentials(_BaseCredentials):
    """Explicit SA credential — identity: APP."""
    @classmethod
    def from_service_account_file(
        cls, filename: str, **kwargs: object,
    ) -> "Credentials": ...
    @classmethod
    def from_service_account_info(
        cls, info: dict, **kwargs: object,
    ) -> "Credentials": ...
    def with_subject(self, subject: str) -> "Credentials": ...
    def with_scopes(self, scopes: list[str]) -> "Credentials": ...
