"""Public API for file_header_sniffer_lib."""

from .core import (
    Sniffer,
    FileSignature,
    SniffResult,
)

__all__ = ["Sniffer", "FileSignature", "SniffResult"]
