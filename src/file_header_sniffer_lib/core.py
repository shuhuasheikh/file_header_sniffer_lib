"""File type identification by magic-number signature.

Reads the first N bytes of a file and matches them against a table of
magic-number signatures. Returns the matched type name, or None if no
signature matches.

Design decisions:
  - Signatures are matched in registration order, not by signature length.
    This keeps behavior deterministic and predictable: the first signature
    that matches wins. Callers who want longest-match-first can register in
    that order. Trying to auto-sort by length would surprise users who
    register a specific signature for a specific format that happens to
    share a prefix with another format (e.g., ZIP-based formats).
  - Signatures are compared at their own offset only. A signature at
    offset 0 of length 4 requires bytes[0:4] to equal it; we do not scan
    for the signature at other offsets. This is a deliberate limitation:
    it keeps the API simple and the behavior deterministic.
  - read_bytes is a separate method so callers can inspect what was
    actually read without re-opening the file.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import BinaryIO, List, Optional


@dataclass(frozen=True)
class FileSignature:
    """A single magic-number signature for one file type.

    Attributes:
        type_name: Human-readable identifier, e.g. "png".
        magic: The exact bytes to match.
        offset: Byte offset in the file where the signature must appear.
    """

    type_name: str
    magic: bytes
    offset: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.magic, (bytes, bytearray)):
            raise TypeError("magic must be bytes")
        if len(self.magic) == 0:
            raise ValueError("magic must be non-empty")
        if self.offset < 0:
            raise ValueError("offset must be non-negative")


@dataclass(frozen=True)
class SniffResult:
    """Outcome of a sniff operation.

    Attributes:
        type_name: The matched type name, or None if no signature matched.
        matched_signature: The FileSignature that matched, or None.
        bytes_read: The actual bytes read from the file (may be shorter
            than max_bytes if the file is small).
    """

    type_name: Optional[str]
    matched_signature: Optional[FileSignature]
    bytes_read: bytes


class Sniffer:
    """Identifies files by matching their header bytes against signatures.

    The built-in signature table covers common formats. Callers can add
    custom signatures via register().
    """

    def __init__(self) -> None:
        self._signatures: List[FileSignature] = []
        self._register_builtin_signatures()

    def _register_builtin_signatures(self) -> None:
        self.register(FileSignature("png", b"\x89PNG\r\n\x1a\n"))
        self.register(FileSignature("jpg", b"\xff\xd8\xff"))
        self.register(FileSignature("gif", b"GIF87a"))
        self.register(FileSignature("gif", b"GIF89a"))
        self.register(FileSignature("pdf", b"%PDF"))
        self.register(FileSignature("zip", b"PK\x03\x04"))
        self.register(FileSignature("gzip", b"\x1f\x8b"))
        self.register(FileSignature("elf", b"\x7fELF"))
        self.register(FileSignature("rtf", b"{\\rtf"))
        self.register(FileSignature("tar_ustar", b"ustar", offset=257))

    def register(self, signature: FileSignature) -> None:
        """Add a signature to the sniffer's table.

        Signatures are checked in registration order; the first match wins.
        """
        self._signatures.append(signature)

    def signatures(self) -> List[FileSignature]:
        """Return a copy of the current signature table."""
        return list(self._signatures)

    def read_bytes(self, file: BinaryIO, max_bytes: int = 512) -> bytes:
        """Read up to max_bytes from the current position of file.

        Seeks back to the original position after reading, so the file
        cursor is left untouched.

        Raises ValueError if max_bytes is negative.
        """
        if max_bytes < 0:
            raise ValueError("max_bytes must be non-negative")
        original = file.tell()
        try:
            return file.read(max_bytes)
        finally:
            file.seek(original)

    def sniff(self, file: BinaryIO, max_bytes: int = 512) -> SniffResult:
        """Sniff an open binary file and return the best match.

        Reads up to max_bytes bytes (or fewer if the file is shorter) and
        tests each signature in registration order. The first signature
        whose magic bytes match at its offset wins.

        Args:
            file: An open binary file object (mode 'rb').
            max_bytes: Maximum number of header bytes to read.

        Returns:
            A SniffResult. type_name is None if nothing matched.

        Raises:
            ValueError: If max_bytes is negative.
            TypeError: If file is not a binary stream (text mode).
        """
        if max_bytes < 0:
            raise ValueError("max_bytes must be non-negative")

        if isinstance(file.read(0), str):
            raise TypeError("file must be opened in binary mode")

        data = self.read_bytes(file, max_bytes)

        for sig in self._signatures:
            end = sig.offset + len(sig.magic)
            if end > len(data):
                continue
            if data[sig.offset:end] == sig.magic:
                return SniffResult(
                    type_name=sig.type_name,
                    matched_signature=sig,
                    bytes_read=data,
                )

        return SniffResult(type_name=None, matched_signature=None, bytes_read=data)
