import 'dart:typed_data';
import 'dart:convert';

import 'package:crypto/crypto.dart' as crypto;
import 'package:cryptography/cryptography.dart' as cryptography;

import 'utils.dart';
import 'wordlist.dart';

Future<String> mnemonicToSeed(String mnemonic, {String passphrase = ''}) async {
  assert(mnemonic.isNotEmpty, 'Mnemonic must not be empty');

  // use pbkdf2 to generate a seed from the mnemonic
  final pbkdf2 = cryptography.Pbkdf2(
    bits: 512,
    iterations: 2048,
    macAlgorithm: cryptography.Hmac.sha512(),
  );
  final salt = 'mnemonic$passphrase';
  // Convert the mnemonic to bytes
  final mnemonicBytes = utf8.encode(mnemonic);
  final secretKey = cryptography.SecretKey(mnemonicBytes);
  final nonce = utf8.encode(salt);
  final key = await pbkdf2.deriveKey(secretKey: secretKey, nonce: nonce);
  return bytesToHex(Uint8List.fromList(await key.extractBytes()));
}

int _checksumBit(int i, List<int> checksum) {
  final checksumIndex = i ~/ 8;
  final checksumByte = checksum[checksumIndex];
  // get the bit position within the byte
  // i % 8 gives the position of the bit in the byte (0-7)
  // 7 - (i % 8) flips the bit order to match the expected order
  // e.g. if i = 0, we want the most significant bit of the byte
  // if i = 1, we want the second most significant bit, etc.
  // this gives us the bit value (0 or 1) at that position
  return (checksumByte >> (7 - (i % 8))) & 1;
}

bool mnemonicValid(String mnemonic) {
  assert(mnemonic.isNotEmpty, 'Mnemonic must not be empty');
  // create a bigint from the mnemonic words
  var bigint = BigInt.zero;
  final words = mnemonic.split(' ');
  var firstWord = true;
  for (final word in words) {
    if (word.isEmpty) return false; // empty word in mnemonic
    // find the index of the word in the wordlist
    final wordIndex = wordList.indexOf(word);
    if (wordIndex == -1) return false; // Invalid word in mnemonic
    if (firstWord) {
      firstWord = false;
    } else {
      // shift the bigint left by 11 bits for each word
      bigint <<= 11;
    }
    // add the word index
    bigint += BigInt.from(wordIndex);
  }
  // extract the checksum bits from the bigint
  final checksumBitCount =
      words.length * 11 ~/ 33; // one checksum bit for every 33 bits
  final checksumBits = List<int>.generate(checksumBitCount, (i) {
    final result = (bigint & BigInt.one).toInt();
    bigint >>= 1; // shift right to get the next bit
    return result;
  }).reversed.toList(); // reverse to get the bits in the correct order

  // calculate the expected checksum from the original mnemonic
  final entropy = bigIntToBytes(bigint);
  final checksum = crypto.sha256.convert(entropy).bytes;
  // compare the checksum bits with the expected checksum bits
  for (var i = 0; i < checksumBitCount; i++) {
    final expectedBit = _checksumBit(i, checksum);
    if (expectedBit != checksumBits[i]) {
      return false; // checksum does not match
    }
  }
  return true; // mnemonic is valid
}

String mnemonicFromEntropy(Uint8List entropy) {
  if (entropy.length < 16 || entropy.length > 32) {
    throw ArgumentError('invalid entropy length');
  }
  if (entropy.length % 4 != 0) {
    throw ArgumentError('entropy length must be a multiple of 4');
  }
  var bigint = bytesToBigInt(entropy);

  // create checksum
  final checksumBitCount = entropy.length ~/ 4;
  final checksum = crypto.sha256.convert(entropy).bytes;

  // append checksum to the end of the entropy
  for (var i = 0; i < checksumBitCount; i++) {
    final checksumBit = _checksumBit(i, checksum);

    // shift the bigint left by 1 and add the checksum bit
    bigint = (bigint << 1) + BigInt.from(checksumBit);
  }

  // calculate the number of words needed
  final numWords = (entropy.length * 8 + checksumBitCount) ~/ 11;
  // create a list to hold the mnemonic words
  final mnemonicWords = <String>[];
  for (var i = 0; i < numWords; i++) {
    // get the index of the word in the wordlist
    final wordIndex = bigint & BigInt.from(2047); // bit mask last 11 bits
    // add the word to the mnemonic words list
    mnemonicWords.insert(0, wordList[wordIndex.toInt()]);
    // shift the bigint right by 11 bits for the next word
    bigint >>= 11;
  }

  return mnemonicWords.join(' ');
}
