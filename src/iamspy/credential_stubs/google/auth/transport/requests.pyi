class Request:
    def __call__(self, url: str, method: str = ..., body: bytes | None = ...,
                 headers: dict | None = ..., timeout: int | None = ...,
                 **kwargs: object) -> object: ...
