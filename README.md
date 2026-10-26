# file_header_sniffer_lib

Reads the first N bytes of a file and identifies its type by magic-number signature.

## Usage

```python
import io
from file_header_sniffer_lib import Sniffer, FileSignature

sniffer = Sniffer()

with io.BytesIO(b"\x89PNG\r\n\x1a\n") as f:
    result = sniffer.sniff(f)
    print(result.type_name)  # "png"
    print(result.matched_signature)  # FileSignature(type_name="png", ...)
    print(result.bytes_read[:8])  # b'\x89PNG\r\n\x1a\n'

# Register a custom signature
sniffer.register(FileSignature("my_format", b"MYFMT", offset=0))
```

## Why this exists

When indexing or validating uploaded files, you often cannot trust the
file extension. Checking the magic-number header is a fast, reliable first
pass. This library does exactly that and nothing more — no full parser, no
content sniffing beyond the header, no MIME-type negotiation.

The trade-off: magic numbers can collide or be absent. A ZIP file and an
Office `.docx` share the same `PK\x03\x04` prefix; this library reports
`zip` for both. If you need deeper discrimination, parse the format.

## Edge cases you will hit

- **Shared prefixes**: ZIP-based formats (Office Open XML, JAR, EPUB) all
  match the `zip` signature. The first registered signature wins; there is
  no automatic longest-match resolution.
- **Short files**: if the file is shorter than the signature at its offset,
  that signature is skipped, not matched.
- **Text-mode files**: passing a file opened in text mode raises
  `TypeError`; always use `"rb"`.
- **Offset signatures**: `tar_ustar` is matched at offset 257, so
  `max_bytes` must be at least 262 to detect it.

## Exports

- `Sniffer` — the main class. Methods: `sniff(file, max_bytes=512)`,
  `read_bytes(file, max_bytes=512)`, `register(signature)`,
  `signatures()`.
- `FileSignature` — a `dataclass` with `type_name: str`, `magic: bytes`,
  `offset: int = 0`.
- `SniffResult` — a `dataclass` with `type_name: Optional[str]`,
  `matched_signature: Optional[FileSignature]`, `bytes_read: bytes`.
