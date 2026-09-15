from __future__ import annotations


class ProtocolError(ValueError):
    """A stable PCP protocol failure."""

    def __init__(self, code: str, message: str, *, retryable: bool = False):
        super().__init__(message)
        self.code = code
        self.message = message
        self.retryable = retryable

    def as_dict(self) -> dict[str, object]:
        return {
            "spec_version": "pcp/0.1",
            "type": "pcp_error",
            "code": self.code,
            "message": self.message,
            "retryable": self.retryable,
            "path": None,
            "grant_id": None,
            "subject_id": None,
        }
