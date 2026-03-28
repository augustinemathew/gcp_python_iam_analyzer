from google.auth.credentials import Credentials
from typing import Optional, Sequence, Tuple

def default(
    scopes: Optional[Sequence[str]] = ...,
    request: Optional[object] = ...,
    quota_project_id: Optional[str] = ...,
    default_scopes: Optional[Sequence[str]] = ...,
) -> Tuple[Credentials, Optional[str]]: ...
