import io
import os
import struct
import tempfile
import unittest

from file_header_sniffer_lib import Sniffer, FileSignature, SniffResult


class TestSniffer(unittest.TestCase):

    def setUp(self):
        self.sniffer = Sniffer()

    # --- Builtin signature detection (happy path) ---

    def test_png(self):
        data = b"\x89PNG\r\n\x1a\n" + b"\x00" * 20
        result = self.sniffer.sniff(io.BytesIO(data))
        self.assertEqual(result.type_name, "png")

    def test_jpg(self):
        data = b"\xff\xd8\xff\xe0" + b"\x00" * 20
        result = self.sniffer.sniff(io.BytesIO(data))
        self.assertEqual(result.type_name, "jpg")

    def test_gif87a(self):
        data = b"GIF87a" + b"\x00" * 20
        result = self.sniffer.sniff(io.BytesIO(data))
        self.assertEqual(result.type_name, "gif")

    def test_gif89a(self):
        data = b"GIF89a" + b"\x00" * 20
        result = self.sniffer.sniff(io.BytesIO(data))
        self.assertEqual(result.type_name, "gif")

    def test_pdf(self):
        data = b"%PDF-1.4\n" + b"\x00" * 20
        result = self.sniffer.sniff(io.BytesIO(data))
        self.assertEqual(result.type_name, "pdf")

    def test_zip(self):
        data = b"PK\x03\x04" + b"\x00" * 20
        result = self.sniffer.sniff(io.BytesIO(data))
        self.assertEqual(result.type_name, "zip")

    def test_gzip(self):
        data = b"\x1f\x8b\x08" + b"\x00" * 20
        result = self.sniffer.sniff(io.BytesIO(data))
        self.assertEqual(result.type_name, "gzip")

    def test_elf(self):
        data = b"\x7fELF" + b"\x00" * 20
        result = self.sniffer.sniff(io.BytesIO(data))
        self.assertEqual(result.type_name, "elf")

    def test_rtf(self):
        data = b"{\\rtf1\\ansi" + b"\x00" * 20
        result = self.sniffer.sniff(io.BytesIO(data))
        self.assertEqual(result.type_name, "rtf")

    def test_tar_ustar_at_offset_257(self):
        # Minimal tar header: 257 zero bytes, then "ustar", then padding.
        data = b"\x00" * 257 + b"ustar" + b"\x00" * 100
        result = self.sniffer.sniff(io.BytesIO(data), max_bytes=512)
        self.assertEqual(result.type_name, "tar_ustar")

    # --- No match ---

    def test_unknown_returns_none(self):
        data = b"hello world this is not a known format\n"
        result = self.sniffer.sniff(io.BytesIO(data))
        self.assertIsNone(result.type_name)
        self.assertIsNone(result.matched_signature)
        self.assertEqual(result.bytes_read, data)

    def test_empty_file(self):
        result = self.sniffer.sniff(io.BytesIO(b""))
        self.assertIsNone(result.type_name)
        self.assertEqual(result.bytes_read, b"")

    # --- Edge cases ---

    def test_file_shorter_than_signature(self):
        data = b"\xff\xd8"  # partial jpg
        result = self.sniffer.sniff(io.BytesIO(data))
        self.assertIsNone(result.type_name)

    def test_signature_at_offset_skipped_if_data_too_short(self):
        data = b"\x00" * 10  # shorter than 257+5 required for tar
        result = self.sniffer.sniff(io.BytesIO(data), max_bytes=512)
        self.assertIsNone(result.type_name)

    def test_max_bytes_zero(self):
        data = b"\x89PNG\r\n\x1a\n"
        result = self.sniffer.sniff(io.BytesIO(data), max_bytes=0)
        self.assertIsNone(result.type_name)
        self.assertEqual(result.bytes_read, b"")

    def test_max_bytes_negative_raises(self):
        with self.assertRaises(ValueError):
            self.sniffer.sniff(io.BytesIO(b"\x89PNG"), max_bytes=-1)

    def test_read_bytes_negative_raises(self):
        with self.assertRaises(ValueError):
            self.sniffer.read_bytes(io.BytesIO(b"\x89PNG"), max_bytes=-1)

    def test_read_bytes_restores_position(self):
        stream = io.BytesIO(b"\x89PNG\r\n\x1a\n\x00" * 10)
        stream.seek(3)
        _ = self.sniffer.read_bytes(stream, max_bytes=8)
        self.assertEqual(stream.tell(), 3)

    def test_sniff_does_not_move_cursor(self):
        stream = io.BytesIO(b"\x89PNG\r\n\x1a\n" + b"\x00" * 40)
        stream.seek(5)
        _ = self.sniffer.sniff(stream, max_bytes=16)
        self.assertEqual(stream.tell(), 5)

    def test_text_mode_file_raises_type_error(self):
        stream = io.StringIO("some text")
        with self.assertRaises(TypeError):
            self.sniffer.sniff(stream)

    # --- Custom signatures ---

    def test_custom_signature_matches(self):
        self.sniffer.register(FileSignature("custom", b"CUStOM"))
        result = self.sniffer.sniff(io.BytesIO(b"CUStOM12345"))
        self.assertEqual(result.type_name, "custom")

    def test_custom_signature_with_offset(self):
        self.sniffer.register(FileSignature("custom_off", b"MARK", offset=10))
        data = b"\x00" * 10 + b"MARK" + b"\x00" * 5
        result = self.sniffer.sniff(io.BytesIO(data), max_bytes=64)
        self.assertEqual(result.type_name, "custom_off")

    def test_first_registered_signature_wins_on_prefix_conflict(self):
        """Two signatures sharing a prefix: first registered wins."""
        sniffer = Sniffer()
        sniffer.register(FileSignature("short", b"AB"))
        sniffer.register(FileSignature("long", b"ABCDE"))
        result = sniffer.sniff(io.BytesIO(b"ABCDE"))
        self.assertEqual(result.type_name, "short")

    def test_custom_empty_magic_raises(self):
        with self.assertRaises(ValueError):
            FileSignature("bad", b"")

    def test_custom_negative_offset_raises(self):
        with self.assertRaises(ValueError):
            FileSignature("bad", b"AB", offset=-1)

    def test_custom_non_bytes_magic_raises(self):
        with self.assertRaises(TypeError):
            FileSignature("bad", "not bytes")  # type: ignore[arg-type]

    # --- Real file on disk ---

    def test_real_png_file(self):
        # Minimal valid PNG header
        png_header = (
            b"\x89PNG\r\n\x1a\n"
            + struct.pack(">I", 13)
            + b"IHDR"
            + b"\x00" * 17
            + b"IEND"
            + struct.pack(">I", 0)
            + b"\xae\x42\x60\x82"
        )
        with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as f:
            f.write(png_header)
            f.flush()
            path = f.name
        try:
            with open(path, "rb") as real_file:
                result = self.sniffer.sniff(real_file)
            self.assertEqual(result.type_name, "png")
        finally:
            os.unlink(path)

    def test_sniff_result_fields(self):
        result = self.sniffer.sniff(io.BytesIO(b"\x89PNG\r\n\x1a\n"))
        self.assertIsInstance(result, SniffResult)
        self.assertEqual(result.type_name, "png")
        self.assertIsInstance(result.matched_signature, FileSignature)
        self.assertTrue(result.bytes_read.startswith(b"\x89PNG"))

    def test_signatures_returns_copy(self):
        sigs = self.sniffer.signatures()
        original_len = len(sigs)
        sigs.clear()
        self.assertEqual(len(self.sniffer.signatures()), original_len)


if __name__ == "__main__":
    unittest.main()
