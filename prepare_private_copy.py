"""Add a required privacy dependency without moving any Mach-O sections or changing code."""
import argparse
import hashlib
import json
import struct
from pathlib import Path

EXPECTED = '447792aacd73cec65cb850da86e39f8915cdd6526424874016e2ed0c44c9bc69'
DEPENDENCY = '@loader_path/libDYYCHUnlock.dylib'


def add_dependency(original):
    if len(original) < 32:
        raise ValueError('Truncated Mach-O')
    magic, cpu, subtype, filetype, count, size, flags, reserved = struct.unpack_from('<8I', original)
    if (magic, cpu, filetype) != (0xfeedfacf, 0x100000c, 6):
        raise ValueError('Expected a thin ARM64 Mach-O dylib')
    end = 32 + size
    offset = 32
    first_section = len(original)
    for _ in range(count):
        command, command_size = struct.unpack_from('<II', original, offset)
        if command_size < 8 or offset + command_size > end:
            raise ValueError('Invalid load command bounds')
        if command == 0x19:
            section_count = struct.unpack_from('<I', original, offset + 64)[0]
            if 72 + 80 * section_count > command_size:
                raise ValueError('Invalid segment section count')
            for index in range(section_count):
                section = offset + 72 + 80 * index
                section_offset = struct.unpack_from('<I', original, section + 48)[0]
                section_size = struct.unpack_from('<Q', original, section + 40)[0]
                if section_offset and section_size:
                    first_section = min(first_section, section_offset)
        offset += command_size
    if offset != end or end > len(original):
        raise ValueError('Invalid load command size')
    name = DEPENDENCY.encode() + b'\0'
    command_size = (24 + len(name) + 7) & ~7
    if end + command_size > first_section or any(original[end:end+command_size]):
        raise ValueError('No verified empty header space; refusing to move code')
    command = struct.pack('<6I', 0xc, command_size, 24, 0, 0x10000, 0x10000) + name
    command = command.ljust(command_size, b'\0')
    updated = bytearray(original)
    # Append to preserve the library ordinals used by imports and chained fixups.
    struct.pack_into('<II', updated, 16, count + 1, size + command_size)
    updated[end:end+command_size] = command
    assert updated[first_section:] == original[first_section:]
    return bytes(updated), {'load_command_offset':hex(end), 'load_command_size':command_size,
                            'first_section_offset':hex(first_section), 'code_unchanged':True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('target', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    original = args.target.read_bytes()
    digest = hashlib.sha256(original).hexdigest()
    if digest != EXPECTED:
        raise SystemExit('Unsupported target hash; refusing to modify this build')
    updated, report = add_dependency(original)
    report.update({'input_sha256':digest, 'dependency':DEPENDENCY,
                   'output_sha256':hashlib.sha256(updated).hexdigest(),
                   'signing':'Output must be re-signed by the iOS injection tool before use'})
    if not args.check:
        if not args.output or args.output.resolve() == args.target.resolve():
            raise SystemExit('Provide a separate --output path; the original must be retained')
        shield = args.output.parent / 'libDYYCHUnlock.dylib'
        if not shield.is_file():
            raise SystemExit('Place the compiled libDYYCHUnlock.dylib beside the output first')
        with args.output.open('xb') as handle:
            handle.write(updated)
        report['output'] = str(args.output.resolve())
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
