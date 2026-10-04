import errno
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from local_input import read_local_file


class InputTests(unittest.TestCase):
    def test_failed_stream_construction_closes_descriptor(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "input"
            path.write_bytes(b"owned local input")
            descriptor = os.open(path, os.O_RDONLY)
            try:
                with patch("local_input.os.open", return_value=descriptor), patch(
                    "local_input.os.fdopen", side_effect=OSError("stream unavailable")
                ):
                    with self.assertRaisesRegex(OSError, "stream unavailable"):
                        read_local_file(path)
                with self.assertRaises(OSError) as closed:
                    os.fstat(descriptor)
                self.assertEqual(closed.exception.errno, errno.EBADF)
            finally:
                try:
                    os.close(descriptor)
                except OSError:
                    pass

    def test_oversized_link_and_nonregular_inputs(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            path=root/"input"
            path.write_bytes(b"x"*9)
            with self.assertRaises(ValueError): read_local_file(path,8)
            link=root/"link"
            link.symlink_to(path)
            with self.assertRaises(ValueError): read_local_file(link)
            with self.assertRaises((ValueError,OSError)): read_local_file(root)
            if hasattr(os,"mkfifo"):
                pipe=root/"pipe"
                os.mkfifo(pipe)
                with self.assertRaises(ValueError): read_local_file(pipe)

    def test_ambiguous_and_deep_json_rejected(self):
        from strict_json import loads
        for value in ('{"setting":true,"setting":false}', '{"number":NaN}', '['*2000+'0'+']'*2000):
            with self.subTest(value=value[:40]),self.assertRaises(ValueError): loads(value)
