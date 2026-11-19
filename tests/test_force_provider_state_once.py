import ctypes as C
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch, Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import force_provider_state_once as force


class ForceStateTests(unittest.TestCase):
    def test_live_capture_decoder(self):
        folder = Path(r'D:\Marathon-preservation\analysis\provider-caller-reader-20261112-212818')
        pages = {}
        for number in (1, 2, 3):
            for row in json.loads((folder / f'result-{number:06}.json').read_text())['ranges']:
                if row.get('bytes') == 4096:
                    pages[int(row['address'], 16)] = bytes.fromhex(row['hex'])
        base = 0x7FF72FBB0000
        reference = pages[base + 0x3658D000][0x650:0x668]
        reads = []

        def reader(address, size):
            self.assertEqual(size, 4096)
            reads.append(address)
            return pages[address]

        obj, metadata = force.decode_reference(reader, base, 0x39D3E000, reference)
        self.assertEqual(obj, 0x247C924E060)
        self.assertLessEqual(len(reads), 16)
        self.assertEqual(metadata['codec_rva'], '0x13b7439e')
        with self.assertRaises(ValueError):
            force.decode_reference(reader, base, 0x39D3E000, bytes(24))

    def test_stall_guards(self):
        value = dict(header=20, state=1, flag=2, appid=3065800, signon_task=4,
                     signon_result=20, http_state=2, http_status=200, received_bytes=313)
        self.assertTrue(force.stalled(value))
        for key, wrong in [('state', 2), ('flag', 0), ('appid', 0), ('header', 0),
                           ('signon_task', 0), ('signon_result', 0), ('http_status', 500),
                           ('http_state', 1), ('received_bytes', 0), ('received_bytes', 0xA001)]:
            altered = {**value, key: wrong}
            self.assertFalse(force.stalled(altered), key)

    def test_wrong_prestate_does_not_open_write_handle(self):
        process = Mock()
        wrong = dict(header=20, state=2, flag=2, appid=3065800, signon_task=4,
                     signon_result=20, http_state=2, http_status=200, received_bytes=313)
        with patch.object(force, 'kernel_signatures'), patch.object(force, 'snapshot', return_value=wrong):
            with self.assertRaises(ValueError):
                force.force_once(process, 1, 0, 0x10000, bytes(24), Path('.'))
        process.k.OpenProcess.assert_not_called()

    @unittest.skipUnless(os.name == 'nt', 'Windows write primitive')
    def test_real_self_process_four_byte_write_preserves_neighbors(self):
        # A test-owned buffer in this Python process, never Marathon.
        words = (C.c_uint32 * 4)(0xA1B2C3D4, 1, 0x10203040, 0xDEADBEEF)
        process = force.Process(os.getpid())
        force.kernel_signatures(process.k)
        handle = process.k.OpenProcess(0x1028, False, os.getpid())
        force.Process.check(handle)
        try:
            self.assertEqual(force.creation_time(process.k, handle), force.creation_time(process.k, process.handle))
            info = force.MemoryInfo()
            self.assertEqual(C.sizeof(info), 48)
            force.Process.check(process.k.VirtualQueryEx(process.handle, C.addressof(words), C.byref(info), C.sizeof(info)))
            self.assertEqual((info.state, info.type), (0x1000, 0x20000))
            force.write_dword_two(process.k, handle, C.addressof(words) + 4)
            self.assertEqual(list(words), [0xA1B2C3D4, 2, 0x10203040, 0xDEADBEEF])
        finally:
            process.k.CloseHandle(handle)
            process.close()


if __name__ == '__main__':
    unittest.main()
