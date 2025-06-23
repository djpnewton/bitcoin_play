// ignore_for_file: avoid_print

import 'dart:convert';
import 'dart:typed_data';
import 'dart:io';

import 'package:args/command_runner.dart';

import 'package:dartcoin/dartcoin.dart';

class ExampleCommand extends Command<void> {
  @override
  final name = 'example';
  @override
  final description = 'An example command to demonstrate key generation.';

  ExampleCommand();

  @override
  void run() {
    final mnemonic =
        'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
    print('Mnemonic words: $mnemonic');

    print('Validating mnemonic: ${mnemonicValid(mnemonic)}');

    final seed = mnemonicToSeed(mnemonic);
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

class SignCommand extends Command<void> {
  @override
  final name = 'sign';
  @override
  final description = 'Sign a message with a private key.';

  SignCommand() {
    // TODO: take the private key from a standard input or file?
    argParser.addOption(
      'private-key',
      abbr: 'p',
      help: 'The private key in hex/WIF/xpriv format.',
      mandatory: true,
    );
    argParser.addOption(
      'message',
      abbr: 'm',
      help: 'The message to sign as a utf8 string',
      mandatory: true,
    );
    argParser.addOption(
      'type',
      abbr: 't',
      help: 'The type of signature to create.',
      allowed: ['bitcoin-signmessage', 'DER'],
      defaultsTo: 'bitcoin-signmessage',
      allowedHelp: {
        'bitcoin-signmessage':
            'Create a signature for a Bitcoin signed message.',
        'DER': 'Create a DER formatted signature.',
      },
    );
    argParser.addOption(
      'network',
      abbr: 'n',
      help: 'The Bitcoin network to use for bitcoin-signmessage signing.',
      allowed: ['mainnet', 'testnet'],
      defaultsTo: 'mainnet',
      allowedHelp: {
        'mainnet': 'Use the main Bitcoin network.',
        'testnet': 'Use the Bitcoin test network.',
      },
    );
    argParser.addOption(
      'script-type',
      abbr: 's',
      help: 'The script type for bitcoin-signmessage.',
      allowed: ['p2pkh', 'p2shP2wpkh', 'p2wpkh'],
      defaultsTo: 'p2pkh',
      allowedHelp: {
        'p2pkh': 'Pay-to-Public-Key-Hash (P2PKH) script type.',
        'p2shP2wpkh':
            'Pay-to-Script-Hash wrapped Pay-to-Witness-Public-Key-Hash.',
        'p2wpkh': 'Pay-to-Witness-Public-Key-Hash (P2WPKH) script type.',
      },
    );
  }

  @override
  void run() {
    final pkRaw = argResults?.option('private-key');
    final message = argResults?.option('message');
    if (pkRaw == null || message == null) {
      // should not happen due to mandatory options, but just in case
      print('Please provide both a private key and a message to sign.');
      return;
    }
    // load private key from hex, WIF, or xpriv
    PrivateKey pk;
    try {
      final pkBytes = hexToBytes(pkRaw);
      pk = PrivateKey.fromPrivateKey(pkBytes);
    } catch (e) {
      // If the private key is not in hex format, try WIF or xpriv
      try {
        pk = PrivateKey.fromWif(pkRaw);
      } catch (e) {
        try {
          pk = PrivateKey.fromXPrv(pkRaw);
        } catch (e) {
          print('Invalid private key format: $pkRaw');
          return;
        }
      }
    }
    final type = argResults?.option('type') ?? 'bitcoin-signmessage';
    if (type == 'DER') {
      // sign the message hash in DER format
      final signature = derSign(pk, utf8.encode(message));
      // print the signature in hex format
      print('Public Key: ${bytesToHex(signature.publicKey)}');
      print('Signature (DER): ${bytesToHex(signature.signature)}');
    } else if (type == 'bitcoin-signmessage') {
      // get the network and script type
      final network = switch (argResults?.option('network')) {
        'mainnet' => Network.mainnet,
        'testnet' => Network.testnet,
        _ => throw ArgumentError('Invalid network type.'),
      };
      final scriptType = switch (argResults?.option('script-type')) {
        'p2pkh' => ScriptType.p2pkh,
        'p2shP2wpkh' => ScriptType.p2shP2wpkh,
        'p2wpkh' => ScriptType.p2wpkh,
        _ => throw ArgumentError('Invalid script type.'),
      };
      // sign the message hash
      final signature = bitcoinSignedMessageSign(
        pk,
        utf8.encode(message),
        network,
        scriptType,
      );
      // print the signature
      print('Address: ${signature.address}');
      print('Signature: ${signature.signature}');
    }
  }
}

class VerifyCommand extends Command<void> {
  @override
  final name = 'verify';
  @override
  final description = 'Verify a signed message with a public key.';

  VerifyCommand() {
    argParser.addOption(
      'public-key',
      abbr: 'p',
      help: 'The public key in hex format. Or a Bitcoin address.',
      mandatory: true,
    );
    argParser.addOption(
      'message',
      abbr: 'm',
      help: 'The original message that was signed.',
      mandatory: true,
    );
    argParser.addOption(
      'signature',
      abbr: 's',
      help: 'The signature to verify.',
      mandatory: true,
    );
  }

  @override
  void run() {
    final pubKeyRaw = argResults?.option('public-key');
    final message = argResults?.option('message');
    final signature = argResults?.option('signature');
    if (pubKeyRaw == null || message == null || signature == null) {
      print('Please provide a public key, message, and signature to verify.');
      return;
    }
    try {
      // check if valid public key
      final pubKeyBytes = hexToBytes(pubKeyRaw);
      final pk = PublicKey.fromPublicKey(pubKeyBytes);
      // verify the signature
      final result = derVerify(pk, utf8.encode(message), hexToBytes(signature));
      print('Signature valid: $result');
    } catch (e) {
      // if not a valid public key, try to parse it as a Bitcoin address
      try {
        final result = bitcoinSignedMessageVerify(
          pubKeyRaw,
          utf8.encode(message),
          signature,
        );
        print('Signature valid: $result');
      } catch (e) {
        print('Invalid public key or Bitcoin address: $pubKeyRaw');
        return;
      }
    }
  }
}

class PrivateKeyCommand extends Command<void> {
  @override
  final name = 'private-key';
  @override
  final description = 'Format a private key to WIF';
  PrivateKeyCommand() {
    // TODO: take the private key from a standard input or file?
    argParser.addOption(
      'private-key',
      abbr: 'p',
      help: 'The private key in hex format.',
      mandatory: true,
    );
  }
  @override
  void run() {
    final pkRaw = argResults?.option('private-key');
    if (pkRaw == null) {
      print('Please provide a private key in hex format.');
      return;
    }
    try {
      final pkBytes = hexToBytes(pkRaw);
      final pk = PrivateKey.fromPrivateKey(pkBytes);
      final wif = Wif(Network.mainnet, pk.privateKey, true);
      print('WIF: ${wif.toWifString()}');
    } catch (e) {
      print('Invalid private key format: $pkRaw');
    }
  }
}

void main(List<String> args) {
  final runner =
      CommandRunner<void>(
          'dartcoin',
          'A command line interface for the dartcoin library.',
        )
        ..addCommand(ExampleCommand())
        ..addCommand(SignCommand())
        ..addCommand(VerifyCommand())
        ..addCommand(PrivateKeyCommand());
  // ignore: inference_failure_on_untyped_parameter
  runner.run(args).catchError((error) {
    if (error is! UsageException) print('Error: $error\n------\n');
    print(runner.usage);
    exit(64); // Exit code 64 indicates a usage error.
  });
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
