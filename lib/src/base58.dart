import 'dart:typed_data';

import 'utils.dart';

final _alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

String base58Encode(Uint8List input) {
  var result = '';
  // Convert Uint8List to BigInt
  BigInt inputBigInt = bytesToBigInt(input);
  // calc remainder until input is zero
  while (inputBigInt > BigInt.zero) {
    // find the remainder when input is divided by 58
    final remainder = inputBigInt % BigInt.from(58);
    // divide input by 58
    inputBigInt = inputBigInt ~/ BigInt.from(58);
    // prepend the character corresponding to the remainder
    result = _alphabet[remainder.toInt()] + result;
  }
  // handle leading zeros in the input
  for (var byte in input) {
    if (byte == 0) {
      result = '1$result'; // prepend '1' for each leading zero byte
    } else {
      break; // stop when we hit a non-zero byte
    }
  }
  return result;
}

Uint8List base58Decode(String input) {
  var value = BigInt.zero;
  var count = 0;
  // reverse the input string to process from least significant to most
  // significant
  for (var i = input.length - 1; i >= 0; i--) {
    final char = input[i];
    // find the index (value) of the character in the alphabet
    final index = _alphabet.indexOf(char);
    if (index == -1) {
      throw FormatException('Invalid character in Base58 string: $char');
    }
    // calculate the contribution of this character to the final result
    // index * 58^count, where count is the position from the right (0-based)
    value += BigInt.from(index) * BigInt.from(58).pow(count);
    count++;
  }
  // handle leading '1's in the input, which correspond to leading zeros in the output
  var countLeadingOnes = 0;
  for (var i = 0; i < input.length && input[i] == '1'; i++) {
    countLeadingOnes++;
  }
  return Uint8List.fromList(
    List.filled(countLeadingOnes, 0) + bigIntToBytes(value),
  ); // prepend leading zeros based on countLeadingOnes
}

String base58EncodeCheck(Uint8List input) {
  // calculate the checksum using SHA-256 twice
  final checksum = hash256(input);
  // take the first 4 bytes of the checksum
  final checksumBytes = Uint8List.fromList(checksum.sublist(0, 4));
  // concatenate the input with the checksum and base58 encode the result
  return base58Encode(Uint8List.fromList(input + checksumBytes));
}

Uint8List base58DecodeCheck(String input) {
  // decode the Base58 string
  final decoded = base58Decode(input);
  // check if the decoded length is at least 4 bytes (for checksum)
  if (decoded.length < 4) {
    throw FormatException('Base58 string too short for checksum');
  }
  // split the decoded bytes into data and checksum
  final data = decoded.sublist(0, decoded.length - 4);
  final checksum = decoded.sublist(decoded.length - 4);
  // calculate the expected checksum
  final expectedChecksum = hash256(data).sublist(0, 4);
  // compare the checksums
  if (!listEquals(checksum, expectedChecksum)) {
    throw FormatException('Invalid checksum in Base58 string');
  }
  return data; // return the data part without the checksum
}
