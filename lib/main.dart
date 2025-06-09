import 'utils.dart';
import 'mnemonic.dart';
import 'extended_keys.dart';

void main() async {
  final bytes = randomBits(128);
  final bigint = bytesToBigInt(bytes);
  final bytesFromBigInt = bigIntToBytes(bigint);
  print('Random 128-bit number (hex): ${bytesToHex(bytes)}');
  print('As big int: $bigint');
  print('Converted back to bytes:     ${bytesToHex(bytesFromBigInt)}');

  final mnemonic = mnemonicFromEntropy(bytes);
  print('Mnemonic words: ${mnemonic}');

  print('Validating mnemonic: ${mnemonicValid(mnemonic)}');

  final seed = await mnemonicToSeed(mnemonic);
  print('Seed (hex): $seed');

  final masterKey = masterKeyFromSeed(hexToBytes(seed));
  print('Master Extended Key:');
  print('  Private Key: ${bytesToHex(masterKey.privateKey)}');
  print('  Public Key:  ${bytesToHex(masterKey.publicKey)}');
  print('  Chain Code:  ${bytesToHex(masterKey.chainCode)}');
}
