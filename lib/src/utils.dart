import 'dart:math';
import 'dart:typed_data';

import 'ripemd160.dart';
import 'sha256.dart';

String bytesToHex(Uint8List bytes) {
  BigInt value = bytesToBigInt(bytes);
  return value.toRadixString(16).padLeft(bytes.length * 2, '0');
}

Uint8List hexToBytes(String hex) {
  if (hex.length % 2 != 0) {
    throw ArgumentError('Hex string must have an even length');
  }
  // remove any leading '0x' if present
  if (hex.startsWith('0x')) {
    hex = hex.substring(2);
  }
  final byteList = Uint8List(hex.length ~/ 2);
  for (int i = 0; i < hex.length; i += 2) {
    final byte = int.parse(hex.substring(i, i + 2), radix: 16);
    byteList[i ~/ 2] = byte;
  }
  return byteList;
}

Uint8List randomBits(int bits) {
  assert(bits > 0);
  assert(bits % 8 == 0);
  int bytes = bits ~/ 8;
  final byteArray = Uint8List(bytes);
  final rand = Random.secure();
  while (bytes > 0) {
    final byte = rand.nextInt(256); // 2^8
    byteArray[--bytes] = byte;
  }
  return byteArray;
}

BigInt bytesToBigInt(Uint8List bytes) {
  BigInt result = BigInt.zero;
  for (int i = 0; i < bytes.length; i++) {
    result = (result << 8) + BigInt.from(bytes[i]);
  }
  return result;
}

Uint8List bigIntToBytes(BigInt value, {int? minLength}) {
  if (minLength != null && minLength < 0) {
    throw ArgumentError('Length must be non-negative');
  }
  if (value < BigInt.zero) {
    throw ArgumentError('Value must be non-negative');
  }
  final byteList = <int>[];
  while (value > BigInt.zero) {
    byteList.add((value & BigInt.from(0xFF)).toInt());
    value >>= 8;
  }
  if (minLength != null) {
    while (byteList.length < minLength) {
      byteList.add(0);
    }
  }
  return Uint8List.fromList(byteList.reversed.toList());
}

bool listEquals<T>(List<T>? a, List<T>? b) {
  if (a == null) {
    return b == null;
  }
  if (b == null || a.length != b.length) {
    return false;
  }
  if (identical(a, b)) {
    return true;
  }
  for (int index = 0; index < a.length; index += 1) {
    if (a[index] != b[index]) {
      return false;
    }
  }
  return true;
}

/// compute the hash256 (ie SHA-256(SHA-256(data))) of the input data
Uint8List hash256(Uint8List data) {
  final firstHash = sha256(data);
  final secondHash = sha256(firstHash);
  return secondHash;
}

/// compute the hash160 (ie RIPEMD-160(SHA-256(data))) of the input data
Uint8List hash160(Uint8List data) {
  final firstHash = sha256(data);
  final secondHash = ripemd160(firstHash);
  return secondHash;
}

Uint8List compactSize(int x) {
  // https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer
  if (x < 0) {
    throw ArgumentError('Value must be non-negative');
  }
  if (x < 0xFD) {
    return Uint8List.fromList([x]);
  } else if (x <= 0xFFFF) {
    return Uint8List.fromList([0xFD, x & 0xFF, (x >> 8) & 0xFF]);
  } else if (x <= 0xFFFFFFFF) {
    return Uint8List.fromList([
      0xFE,
      x & 0xFF,
      (x >> 8) & 0xFF,
      (x >> 16) & 0xFF,
      (x >> 24) & 0xFF,
    ]);
  } else if (x <= 0x7FFFFFFFFFFFFFFF) {
    return Uint8List.fromList([
      0xFF,
      x & 0xFF,
      (x >> 8) & 0xFF,
      (x >> 16) & 0xFF,
      (x >> 24) & 0xFF,
      (x >> 32) & 0xFF,
      (x >> 40) & 0xFF,
      (x >> 48) & 0xFF,
      (x >> 56) & 0xFF,
    ]);
  } else {
    // wont get hit as 0x7FFFFFFFFFFFFFFF is the max for a signed 64-bit integer
    throw ArgumentError('Integer too large for varint encoding: $x');
  }
}
