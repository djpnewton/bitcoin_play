// ignore_for_file: avoid_relative_lib_imports

import 'dart:convert';

import 'package:test/test.dart';

import '../lib/src/sha256.dart';
import '../lib/src/utils.dart';

void main() {
  test('sha256 specification test values', () {
    expect(
      sha256(hexToBytes('61 62 63'.replaceAll(' ', ''))),
      equals(
        hexToBytes(
          'ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad'
              .replaceAll(' ', ''),
        ),
      ),
    );
    expect(
      sha256(
        hexToBytes(
          '61 62 63 64 62 63 64 65 63 64 65 66 64 65 66 67 65 66 67 68 66 67 68 69 67 68 69 6a 68 69 6a 6b 69 6a 6b 6c 6a 6b 6c 6d 6b 6c 6d 6e 6c 6d 6e 6f 6d 6e 6f 70 6e 6f 70 71'
              .replaceAll(' ', ''),
        ),
      ),
      equals(
        hexToBytes(
          '248d6a61 d20638b8 e5c02693 0c3e6039 a33ce459 64ff2167 f6ecedd4 19db06c1'
              .replaceAll(' ', ''),
        ),
      ),
    );
    expect(
      sha256(hexToBytes('61' * 1000000)),
      equals(
        hexToBytes(
          'cdc76e5c 9914fb92 81a1c7e2 84d73e67 f1809a48 a497200e 046d39cc c7112cd0'
              .replaceAll(' ', ''),
        ),
      ),
    );
  });
  test('sha256 more tests', () {
    expect(
      sha256(utf8.encode('')),
      equals(
        hexToBytes(
          'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        ),
      ),
    );
    expect(
      sha256(utf8.encode('a')),
      equals(
        hexToBytes(
          'ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb',
        ),
      ),
    );
    expect(
      sha256(utf8.encode('hello world')),
      equals(
        hexToBytes(
          'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9',
        ),
      ),
    );
    expect(
      sha256(
        utf8.encode(
          'Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.',
        ),
      ),
      equals(
        hexToBytes(
          '2d8c2f6d978ca21712b5f6de36c9d31fa8e96a4fa5d8ff8b0188dfb9e7c171bb',
        ),
      ),
    );
    expect(
      sha256(hexToBytes('ffffff')),
      equals(
        hexToBytes(
          '5ae7e6a42304dc6e4176210b83c43024f99a0bce9a870c3b6d2c95fc8ebfb74c',
        ),
      ),
    );
  });
}
