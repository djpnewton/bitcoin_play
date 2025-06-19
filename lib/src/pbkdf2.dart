import 'dart:typed_data';

import 'hmac.dart';

enum MacAlgorithm { hmacSha256, hmacSha512 }

Uint8List mac(MacAlgorithm algorithm, Uint8List key, Uint8List message) {
  return switch (algorithm) {
    MacAlgorithm.hmacSha256 => hmac(Hash.sha256, key, message),
    MacAlgorithm.hmacSha512 => hmac(Hash.sha512, key, message),
  };
}

Uint8List _pbkdf2Block(
  MacAlgorithm algorithm,
  Uint8List key,
  Uint8List salt,
  int blockIndex,
  int iterations,
) {
  final blockIndexBytes = Uint8List(4)
    ..buffer.asByteData().setUint32(0, blockIndex);

  final initialInput = Uint8List.fromList([...salt, ...blockIndexBytes]);

  var output = mac(algorithm, key, initialInput);

  var result = output;

  for (int i = 1; i < iterations; i++) {
    output = mac(algorithm, key, output);
    for (int j = 0; j < output.length; j++) {
      result[j] ^= output[j];
    }
  }

  return result;
}

Uint8List pbkdf2(
  MacAlgorithm algorithm,
  Uint8List key,
  Uint8List salt, {
  int iterations = 2048,
  int bits = 512,
}) {
  final blockSize = switch (algorithm) {
    MacAlgorithm.hmacSha256 => 32, // SHA-256 produces 32 bytes
    MacAlgorithm.hmacSha512 => 64, // SHA-512 produces 64 bytes
  };

  final keyLength = (bits + 7) ~/ 8; // Convert bits to bytes
  final numBlocks = (keyLength + blockSize - 1) ~/ blockSize;

  if (keyLength <= 0) {
    throw ArgumentError('bits must be as least 8.');
  }
  if (iterations <= 0) {
    throw ArgumentError('iterations must be at least 1.');
  }

  final result = Uint8List(keyLength);

  for (int i = 1; i <= numBlocks; i++) {
    final block = _pbkdf2Block(algorithm, key, salt, i, iterations);
    result.setRange(
      (i - 1) * blockSize,
      (i * blockSize).clamp(0, keyLength),
      block,
    );
  }

  return result.sublist(0, keyLength);
}
