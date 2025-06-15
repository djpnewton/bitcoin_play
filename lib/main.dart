// ignore_for_file: avoid_print

import 'dart:typed_data';

import 'package:args/command_runner.dart';

import 'src/common.dart';
import 'src/utils.dart';
import 'src/mnemonic.dart';
import 'src/keys.dart';

class ExampleCommand extends Command<void> {
  @override
  final name = 'example';
  @override
  final description = 'An example command to demonstrate key generation.';

  ExampleCommand();

  @override
  void run() async {
    final mnemonic =
        'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
    print('Mnemonic words: $mnemonic');

    print('Validating mnemonic: ${mnemonicValid(mnemonic)}');

    final seed = await mnemonicToSeed(mnemonic);
    print('Seed (hex): $seed');

    final masterKey = PrivateKey.fromSeed(hexToBytes(seed));
    print('Master Extended Key:');
    print('  Private Key: ${bytesToHex(masterKey.privateKey)}');
    print('  Public Key:  ${bytesToHex(masterKey.publicKey)}');
    print('  Chain Code:  ${bytesToHex(masterKey.chainCode)}');

    final childKey = masterKey.childPrivateKey(0x80000000, hardened: true);
    print('Child Extended Key m/0\':');
    print('  Private Key:  ${bytesToHex(childKey.privateKey)}');
    print('  Public Key:   ${bytesToHex(childKey.publicKey)}');
    print('  Chain Code:   ${bytesToHex(childKey.chainCode)}');
    print('  Depth:        ${intToHex(childKey.depth)}');
    print('  Parent Fingerprint: ${intToHex(childKey.parentFingerprint)}');
    print('  Child Number: ${intToHex(childKey.childNumber)}');
    final xprv = childKey.xprv();
    print('  xprv: $xprv');
    final childKeyParsed = PrivateKey.fromXPrv(xprv);
    print('Parsed Child Extended Key:');
    print('  Private Key:  ${bytesToHex(childKeyParsed.privateKey)}');
    print('  Public Key:   ${bytesToHex(childKeyParsed.publicKey)}');
    print('  Chain Code:   ${bytesToHex(childKeyParsed.chainCode)}');
    print('  Depth:        ${intToHex(childKeyParsed.depth)}');
    print(
      '  Parent Fingerprint: ${intToHex(childKeyParsed.parentFingerprint)}',
    );
    print('  Child Number: ${intToHex(childKeyParsed.childNumber)}');

    final childPubKey = masterKey.childPublicKey(1);
    print('Child Public Key m/1:');
    print('  Public Key:   ${bytesToHex(childPubKey.publicKey)}');
    print('  Chain Code:   ${bytesToHex(childPubKey.chainCode)}');
    print('  Depth:        ${intToHex(childPubKey.depth)}');
    print('  Parent Fingerprint: ${intToHex(childPubKey.parentFingerprint)}');
    print('  Child Number: ${intToHex(childPubKey.childNumber)}');
    final xpub = childPubKey.xpub();
    print('  xpub: $xpub');
    final childPubKeyParsed = PublicKey.fromXPub(xpub);
    print('Parsed Child Public Key:');
    print('  Public Key:   ${bytesToHex(childPubKeyParsed.publicKey)}');
    print('  Chain Code:   ${bytesToHex(childPubKeyParsed.chainCode)}');
    print('  Depth:        ${intToHex(childPubKeyParsed.depth)}');
    print(
      '  Parent Fingerprint: ${intToHex(childPubKeyParsed.parentFingerprint)}',
    );
    print('  Child Number: ${intToHex(childPubKeyParsed.childNumber)}');

    var address = childPubKey.address(network: Network.mainnet);
    print('P2PKH Address (m/1): $address');
    address = childPubKey.address(network: Network.testnet);
    print('P2PKH Address (m/1) Testnet: $address');
    address = childPubKey.address(
      network: Network.mainnet,
      scriptType: ScriptType.p2shP2wpkh,
    );
    print('P2SH-P2WPKH Address (m/1): $address');
    address = childPubKey.address(
      network: Network.testnet,
      scriptType: ScriptType.p2shP2wpkh,
    );
    print('P2SH-P2WPKH Address (m/1) Testnet: $address');
    address = childPubKey.address(
      network: Network.mainnet,
      scriptType: ScriptType.p2wpkh,
    );
    print('P2WPKH Address (m/1): $address');
    address = childPubKey.address(
      network: Network.testnet,
      scriptType: ScriptType.p2wpkh,
    );
    print('P2WPKH Address (m/1) Testnet: $address');
  }
}

void main(List<String> args) async {
  CommandRunner<void>(
      'dartcoin',
      'A command line interface for the dartcoin library.',
    )
    ..addCommand(ExampleCommand())
    ..run(args);
}

Uint8List intToBytes(int value) {
  if (value < 0) {
    throw ArgumentError('Value must be non-negative');
  }
  final byteList = <int>[];
  while (value > 0) {
    byteList.add(value & 0xFF);
    value >>= 8;
  }
  return Uint8List.fromList(byteList.reversed.toList());
}

String intToHex(int value) {
  return bytesToHex(intToBytes(value));
}
