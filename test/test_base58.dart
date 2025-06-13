// ignore_for_file: avoid_relative_lib_imports

import 'dart:typed_data';

import 'package:test/test.dart';

import '../lib/base58.dart';
import '../lib/utils.dart';

void main() {
  test('base58Encode', () {
    expect(base58Encode(hexToBytes('')), equals(''));
    expect(base58Encode(hexToBytes('00')), equals('1'));
    expect(base58Encode(hexToBytes('01')), equals('2'));
    expect(base58Encode(hexToBytes('ffffff')), equals('2UzHL'));
  });
  test('base58Decode', () {
    expect(base58Decode(''), equals(Uint8List(0)));
    expect(base58Decode('1'), equals(hexToBytes('00')));
    expect(base58Decode('2'), equals(hexToBytes('01')));
    expect(base58Decode('2UzHL'), equals(hexToBytes('ffffff')));
    expect(() => base58Decode('invalid'), throwsFormatException);
  });
  test('base58EncodeCheck', () {
    expect(base58EncodeCheck(hexToBytes('')), equals('3QJmnh'));
    expect(base58EncodeCheck(hexToBytes('00')), equals('1Wh4bh'));
    expect(base58EncodeCheck(hexToBytes('01')), equals('BXvDbH'));
    expect(base58EncodeCheck(hexToBytes('ffffff')), equals('Ahg1j3Hn3S'));
  });
  test('base58DecodeCheck', () {
    expect(base58DecodeCheck('3QJmnh'), equals(hexToBytes('')));
    expect(base58DecodeCheck('1Wh4bh'), equals(hexToBytes('00')));
    expect(base58DecodeCheck('BXvDbH'), equals(hexToBytes('01')));
    expect(base58DecodeCheck('Ahg1j3Hn3S'), equals(hexToBytes('ffffff')));
    expect(() => base58DecodeCheck('invalid'), throwsFormatException);
  });
}
