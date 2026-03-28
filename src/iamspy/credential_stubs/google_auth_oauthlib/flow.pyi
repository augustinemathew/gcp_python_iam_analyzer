from google.oauth2.credentials import Credentials

class Flow:
    """OAuth web flow — .credentials yields USER identity."""
    credentials: Credentials
    code_verifier: str | None
    redirect_uri: str
    @classmethod
    def from_client_config(
        cls, client_config: dict, scopes: list[str], **kwargs: object,
    ) -> "Flow": ...
    @classmethod
    def from_client_secrets_file(
        cls, client_secrets_file: str, scopes: list[str], **kwargs: object,
    ) -> "Flow": ...
    def authorization_url(self, **kwargs: object) -> tuple[str, str]: ...
    def fetch_token(self, **kwargs: object) -> dict: ...

class InstalledAppFlow(Flow):
    """OAuth installed app flow — .credentials yields USER identity."""
    @classmethod
    def from_client_secrets_file(
        cls, client_secrets_file: str, scopes: list[str], **kwargs: object,
    ) -> "InstalledAppFlow": ...
    def run_local_server(self, **kwargs: object) -> Credentials: ...
    def run_console(self, **kwargs: object) -> Credentials: ...
