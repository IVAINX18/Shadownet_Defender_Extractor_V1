"""Custom exceptions for ShadowNet Defender core layer."""


class NonPEFileError(Exception):
    """Raised when a file cannot be parsed as a valid PE executable."""

    def __init__(self, file_path: str) -> None:
        self.file_path = str(file_path)
        super().__init__(f"File is not a valid PE executable: {self.file_path}")
