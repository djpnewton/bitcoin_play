import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;

import 'secp256k1.dart';
import 'utils.dart';

class MasterExtendedKey {
  Uint8List privateKey;
  Uint8List publicKey;
  Uint8List chainCode;

  MasterExtendedKey(this.privateKey, this.publicKey, this.chainCode);
}

MasterExtendedKey masterKeyFromSeed(Uint8List seed) {
  // hmac sha512 seed with 'Bitcoin seed' to get the master key
  final hmac = crypto.Hmac(crypto.sha512, utf8.encode('Bitcoin seed'));
  final digest = hmac.convert(seed);
  // The first 32 bytes are the private key, the next 32 bytes are the chain code
  final privateKey = Uint8List.fromList(digest.bytes.sublist(0, 32));
  final chainCode = Uint8List.fromList(digest.bytes.sublist(32, 64));
  // The public key is derived from the private key using secp256k1
  final publicKey = pubkeyFromPrivateKey(privateKey);
  return MasterExtendedKey(privateKey, publicKey, chainCode);
}

Uint8List pubkeyFromPrivateKey(Uint8List privateKey) {
  // Derive the public key from the private key using secp256k1
  final point = Secp256k1Point.generator.multiply(bytesToBigInt(privateKey));
  // Convert the point to bytes (compressed format)
  final x = point.x.toRadixString(16).padLeft(64, '0');
  // Compressed public key format: 0x02 or 0x03 + x
  final prefix = (point.y.isEven ? '02' : '03');
  return Uint8List.fromList(hexToBytes(prefix + x));
}
