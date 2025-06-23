// define a hash funtion that inputs a uint8list and returns a uint8list
import 'dart:typed_data';

import 'utils.dart';
import 'secp256k1.dart';
import 'hmac.dart';

BigInt _rfc6979(
  BigInt order,
  Uint8List privateKey,
  Hash hashAlgorithm,
  Uint8List msgHash,
) {
  if (privateKey.length != 32) {
    throw ArgumentError('Private key length must be 32 bytes.');
  }

  final qlen = order.bitLength;
  final hashLength = switch (hashAlgorithm) {
    Hash.sha256 => 32, // SHA-256 digest size
    Hash.sha512 => 64, // SHA-512 digest size
  };

  final rolen = (qlen + 7) ~/ 8;

  final bx = privateKey + msgHash;

  // Step B
  var v = List<int>.filled(hashLength, 0x01);

  // Step C
  var k = List<int>.filled(hashLength, 0x00);

  // Step D
  k = hmac(
    hashAlgorithm,
    Uint8List.fromList(k),
    Uint8List.fromList(v + [0x00] + bx),
  );

  // Step E
  v = hmac(hashAlgorithm, Uint8List.fromList(k), Uint8List.fromList(v));

  // Step F
  k = hmac(
    hashAlgorithm,
    Uint8List.fromList(k),
    Uint8List.fromList(v + [0x01] + bx),
  );

  // Step G
  v = hmac(hashAlgorithm, Uint8List.fromList(k), Uint8List.fromList(v));

  // Step H
  while (true) {
    // Step H1
    var t = <int>[];

    // Step H2
    while (t.length < rolen) {
      v = hmac(hashAlgorithm, Uint8List.fromList(k), Uint8List.fromList(v));
      t += v;
    }

    // Step H3
    final secret = bytesToBigInt(Uint8List.fromList(t));

    if (secret >= BigInt.one && secret < order) {
      return secret;
    }

    k = hmac(
      hashAlgorithm,
      Uint8List.fromList(k),
      Uint8List.fromList(v + [0x00]),
    );
    v = hmac(hashAlgorithm, Uint8List.fromList(k), Uint8List.fromList(v));
  }
}

/// generate a deterministic nonce (k) using RFC 6979
BigInt generateK(Uint8List privateKey, Uint8List msgHash) {
  return _rfc6979(Secp256k1Point.n, privateKey, Hash.sha256, msgHash);
}
