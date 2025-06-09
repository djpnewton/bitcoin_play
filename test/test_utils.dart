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
        hexToBytes(hex), equals(Uint8List.fromList([0x12, 0x34, 0x56, 0x78])));
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
}
