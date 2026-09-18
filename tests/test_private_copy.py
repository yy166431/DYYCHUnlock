import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from prepare_private_copy import add_dependency, DEPENDENCY


class PrivateCopyTests(unittest.TestCase):
    def sample(self):
        header = struct.pack('<8I',0xfeedfacf,0x100000c,0,6,2,184,0,0)
        segment = struct.pack('<II16sQQQQIIII',0x19,152,b'__TEXT',0,8192,0,8192,5,5,1,0)
        section = struct.pack('<16s16sQQ8I',b'__text',b'__TEXT',4096,4096,4096,2,0,0,0,0,0,0)
        dependency = struct.pack('<6I',0xc,32,24,0,0,0) + b'old\0\0\0\0\0'
        return (header+segment+section+dependency).ljust(4096,b'\0')+b'X'*4096

    def test_preserves_sections_and_existing_library_ordinals(self):
        original = self.sample()
        updated, report = add_dependency(original)
        self.assertEqual(updated[32:216],original[32:216])
        self.assertEqual(updated[4096:],original[4096:])
        self.assertEqual(len(updated),len(original))
        self.assertIn(DEPENDENCY.encode(),updated[216:4096])
        self.assertEqual(struct.unpack_from('<I',updated,16)[0],3)
        self.assertTrue(report['code_unchanged'])

    def test_refuses_nonzero_header_slack(self):
        sample = bytearray(self.sample())
        sample[216] = 1
        with self.assertRaises(ValueError):
            add_dependency(sample)

    def test_refuses_wrong_architecture(self):
        sample = bytearray(self.sample())
        struct.pack_into('<I',sample,4,7)
        with self.assertRaises(ValueError):
            add_dependency(sample)


if __name__ == '__main__':
    unittest.main()
