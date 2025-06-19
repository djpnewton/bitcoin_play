import 'dart:typed_data';

import 'sha256.dart';
import 'sha512.dart';

enum Hash { sha256, sha512 }

Uint8List _hash(Hash algorithm, Uint8List data) {
  switch (algorithm) {
    case Hash.sha256:
      return sha256(data);
    case Hash.sha512:
      return sha512(data);
  }
}

Uint8List _computeBlockSizedKey(Hash algorithm, Uint8List key) {
  final blockSize = switch (algorithm) {
    Hash.sha256 => 64,
    Hash.sha512 => 128,
  };
  if (key.length > blockSize) {
    key = _hash(algorithm, key);
  }
  if (key.length < blockSize) {
    key = Uint8List.fromList([
      ...key,
      ...List.filled(blockSize - key.length, 0),
    ]);
  }
  return key;
}

Uint8List hmac(Hash algorithm, Uint8List key, Uint8List message) {
  key = _computeBlockSizedKey(algorithm, key);
  final oKeyPad = Uint8List(key.length);
  final iKeyPad = Uint8List(key.length);
  for (int i = 0; i < key.length; i++) {
    oKeyPad[i] = key[i] ^ 0x5c;
    iKeyPad[i] = key[i] ^ 0x36;
  }

  final innerHash = _hash(
    algorithm,
    Uint8List.fromList([...iKeyPad, ...message]),
  );
  final result = _hash(
    algorithm,
    Uint8List.fromList([...oKeyPad, ...innerHash]),
  );
  return result;
}
