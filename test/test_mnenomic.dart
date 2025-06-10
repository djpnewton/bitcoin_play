import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:bip39/bip39.dart' as bip39;

import '../lib/mnemonic.dart';
import '../lib/utils.dart';

void main() {
  late Uint8List entropy;
  setUp(() async {
    entropy = randomBits(128);
  });
  tearDown(() async {});
  test('create mnemonic', () async {
    final mnemonic = mnemonicFromEntropy(entropy);
    expect(mnemonic.isNotEmpty, isTrue);
    expect(mnemonic.split(' ').length, equals(12));
    expect(mnemonic, equals(bip39.entropyToMnemonic(bytesToHex(entropy))));
  });
  test('create mnemonic from too small entropy', () async {
    final smallEntropy = randomBits(64);
    expect(() => mnemonicFromEntropy(smallEntropy), throwsFormatException);
  });
  test('create mnemonic from large entropy', () async {
    final largeEntropy = randomBits(256);
    final mnemonic = mnemonicFromEntropy(largeEntropy);
    expect(mnemonic.isNotEmpty, isTrue);
    expect(mnemonic.split(' ').length, equals(24));
    expect(mnemonic, equals(bip39.entropyToMnemonic(bytesToHex(largeEntropy))));
  });
  test('create mnemonic from too large entropy', () async {
    final largeEntropy = randomBits(512);
    expect(() => mnemonicFromEntropy(largeEntropy), throwsFormatException);
  });
  test('create mnemonic from invalid entropy length', () async {
    final entropy = randomBits(264);
    expect(() => mnemonicFromEntropy(entropy), throwsFormatException);
  });
  test('mnemonic valid', () async {
    final mnemonic = mnemonicFromEntropy(entropy);
    expect(mnemonicValid(mnemonic), isTrue);
  });
  test('mnemonic invalid', () async {
    final mnemonic = 'this is an invalid mnemonic';
    expect(mnemonicValid(mnemonic), isFalse);
  });
  test('mnemonic to seed', () async {
    final mnemonic = mnemonicFromEntropy(entropy);
    final seed = await mnemonicToSeed(mnemonic);
    expect(seed.isNotEmpty, isTrue);
    expect(seed.length, equals(128)); // 512 bits
    expect(seed, equals(bip39.mnemonicToSeedHex(mnemonic)));
  });
}
