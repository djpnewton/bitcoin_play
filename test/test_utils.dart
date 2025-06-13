// ignore_for_file: avoid_relative_lib_imports

import 'dart:convert';
import 'dart:typed_data';

import 'package:test/test.dart';

import '../lib/utils.dart';

void main() {
  test('bytesToHex() converts bytes to hex string', () {
    var bytes = Uint8List.fromList([0x12, 0x34, 0x56, 0x78]);
    expect(bytesToHex(bytes), equals('12345678'));
  });
  test('hexToBytes() converts hex string to bytes', () {
    var hex = '12345678';
    expect(
      hexToBytes(hex),
      equals(Uint8List.fromList([0x12, 0x34, 0x56, 0x78])),
    );
    expect(() => hexToBytes('hello '), throwsFormatException);
    expect(() => hexToBytes('123'), throwsArgumentError);
  });
  test('randomBits() generates random bytes of specified bit length', () {
    var bits = 128;
    var bytes = randomBits(bits);
    expect(bytes.length, equals(bits ~/ 8));
    expect(bytes.every((byte) => byte >= 0 && byte < 256), isTrue);
    bits = 256;
    bytes = randomBits(bits);
    expect(bytes.length, equals(bits ~/ 8));
    expect(bytes.every((byte) => byte >= 0 && byte < 256), isTrue);
  });
  test('bytesToBigInt() converts bytes to BigInt', () {
    var bytes = Uint8List.fromList([0x01, 0x02, 0x03, 0x04]);
    expect(bytesToBigInt(bytes), equals(BigInt.from(0x01020304)));
  });
  test('bigIntToBytes() converts BigInt to bytes', () {
    var value = BigInt.from(0x01020304);
    var bytes = bigIntToBytes(value);
    expect(bytes, equals(Uint8List.fromList([0x01, 0x02, 0x03, 0x04])));
  });
  test('listEquals() compares two lists for equality', () {
    var list1 = [1, 2, 3];
    var list2 = [1, 2, 3];
    var list3 = [4, 5, 6];
    expect(listEquals(list1, list2), isTrue);
    expect(listEquals(list1, list3), isFalse);
    expect(listEquals<int>(null, null), isTrue);
    expect(listEquals(null, list1), isFalse);
    expect(listEquals(list1, null), isFalse);
  });
  test('hash256() computes double SHA-256 hash', () {
    expect(
      hash256(hexToBytes('')),
      equals(
        hexToBytes(
          '5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456',
        ),
      ),
    );
    expect(
      hash256(hexToBytes('12345678')),
      equals(
        hexToBytes(
          '0757152190e14e5889b1270309d7c8e40219d45e04096fcb97d1b4c5a99064e1',
        ),
      ),
    );
    expect(
      hash256(utf8.encode('hello world')),
      equals(
        hexToBytes(
          'bc62d4b80d9e36da29c16c5d4d9f11731f36052c72401a76c23c0fb5a9b74423',
        ),
      ),
    );
  });
  test('hash160() computes RIPEMD-160 hash after SHA-256', () {
    expect(
      hash160(hexToBytes('')),
      equals(hexToBytes('b472a266d0bd89c13706a4132ccfb16f7c3b9fcb')),
    );
    expect(
      hash160(hexToBytes('12345678')),
      equals(hexToBytes('82c12e3c770a95bd17fd1d983d6b2af2037b7a4b')),
    );
    expect(
      hash160(utf8.encode('hello world')),
      equals(hexToBytes('d7d5ee7824ff93f94c3055af9382c86c68b5ca92')),
    );
  });
}
