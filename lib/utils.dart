import 'dart:math';
import 'dart:typed_data';

String bytesToHex(Uint8List bytes) {
  BigInt value = bytesToBigInt(bytes);
  return value.toRadixString(16).padLeft(bytes.length * 2, '0');
}

Uint8List hexToBytes(String hex) {
  assert(hex.length % 2 == 0, 'Hex string must have an even length');
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
  final rand = new Random.secure();
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

Uint8List bigIntToBytes(BigInt value) {
  final byteList = <int>[];
  while (value > BigInt.zero) {
    byteList.add((value & BigInt.from(0xFF)).toInt());
    value >>= 8;
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
