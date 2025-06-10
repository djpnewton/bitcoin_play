import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;

import 'secp256k1.dart';
import 'utils.dart';

class PublicKey {
  Uint8List publicKey;
  Uint8List chainCode;
  PublicKey(this.publicKey, this.chainCode);
}

class ExtendedKey extends PublicKey {
  Uint8List privateKey;

  ExtendedKey(this.privateKey, Uint8List publicKey, Uint8List chainCode)
      : super(publicKey, chainCode);
}

ExtendedKey masterKeyFromSeed(Uint8List seed) {
  // hmac sha512 seed with 'Bitcoin seed' to get the master key
  final hmac = crypto.Hmac(crypto.sha512, utf8.encode('Bitcoin seed'));
  final digest = hmac.convert(seed);
  // The first 32 bytes are the private key, the next 32 bytes are the chain code
  final privateKey = Uint8List.fromList(digest.bytes.sublist(0, 32));
  final chainCode = Uint8List.fromList(digest.bytes.sublist(32, 64));
  // The public key is derived from the private key using secp256k1
  final publicKey = pubkeyFromPrivateKey(privateKey);
  return ExtendedKey(privateKey, publicKey, chainCode);
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

ExtendedKey? childKeyFromMasterKey(ExtendedKey masterKey, int index,
    {bool hardened = true}) {
  // Check if the index is valid
  if (hardened) {
    if (index >= 2147483648 && index <= 4294967295) {
      throw ArgumentError(
          'Index ($index) must be in the range [2147483648, 4294967295)');
    }
  } else if (index >= 0 && index <= 2147483647) {
    throw ArgumentError('Index ($index) must be in the range [0, 2147483647)');
  }
  // Create a new key from the master key and the index
  final data = hardened
      ? hexToBytes('00' +
          bytesToHex(masterKey.privateKey) +
          index
              .toRadixString(16)
              .padLeft(8, '0')) // '00' + master privkey + 4 byte index
      : hexToBytes(bytesToHex(masterKey.publicKey) +
          index
              .toRadixString(16)
              .padLeft(8, '0')); // master pubkey + 4 byte index
  final hmac = crypto.Hmac(crypto.sha512, masterKey.chainCode);
  final digest = hmac.convert(data);
  // The first 32 bytes are the child private key input, the next 32 bytes are the chain code
  final privateKeyInput = Uint8List.fromList(digest.bytes.sublist(0, 32));
  final chainCode = Uint8List.fromList(digest.bytes.sublist(32, 64));
  // calculate the child private key
  final childPrivateKeyInt =
      (bytesToBigInt(privateKeyInput) + bytesToBigInt(masterKey.privateKey)) %
          Secp256k1Point.n;
  final childPrivateKey = bigIntToBytes(childPrivateKeyInt);
  // The public key is derived from the private key using secp256k1
  final childPublicKey = pubkeyFromPrivateKey(childPrivateKey);
  return ExtendedKey(childPrivateKey, childPublicKey, chainCode);
}

PublicKey? childKeyFromMasterPublicKey(PublicKey masterKey, int index) {
  // Check if the index is valid
  if (index >= 0 && index <= 2147483647) {
    throw ArgumentError('Index ($index) must be in the range [0, 2147483647)');
  }
  // Create a new key from the master key and the index
  final data = hexToBytes(bytesToHex(masterKey.publicKey) +
      index.toRadixString(16).padLeft(8, '0')); // master pubkey + 4 byte index
  final hmac = crypto.Hmac(crypto.sha512, masterKey.chainCode);
  final digest = hmac.convert(data);
  // The first 32 bytes are the child private key input, the next 32 bytes are the chain code
  final privateKeyInput = Uint8List.fromList(digest.bytes.sublist(0, 32));
  final chainCode = Uint8List.fromList(digest.bytes.sublist(32, 64));
  // calculate the child private key
  final childPrivateKeyInt =
      (bytesToBigInt(privateKeyInput) + bytesToBigInt(masterKey.publicKey)) %
          Secp256k1Point.n;
  final childPrivateKey = bigIntToBytes(childPrivateKeyInt);
  // The public key is derived from the private key using secp256k1
  final childPublicKey = pubkeyFromPrivateKey(childPrivateKey);
  return ExtendedKey(childPrivateKey, childPublicKey, chainCode);
}

//TODO: xpub etc...
