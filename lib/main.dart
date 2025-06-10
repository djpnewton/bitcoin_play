import 'utils.dart';
import 'mnemonic.dart';
import 'keys.dart';

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

  final childKey = childKeyFromMasterKey(masterKey, 2147483647, hardened: true);
  if (childKey != null) {
    print('Child Extended Key:');
    print('  Private Key: ${bytesToHex(childKey.privateKey)}');
    print('  Public Key:  ${bytesToHex(childKey.publicKey)}');
    print('  Chain Code:  ${bytesToHex(childKey.chainCode)}');
  } else {
    print('Failed to derive child key.');
  }

  final childPubKey = childKeyFromMasterPublicKey(masterKey, 0);
  if (childPubKey != null) {
    print('Child Public Key:');
    print('  Public Key:  ${bytesToHex(childPubKey.publicKey)}');
    print('  Chain Code:  ${bytesToHex(childPubKey.chainCode)}');
  } else {
    print('Failed to derive child public key.');
  }

  //final address = addressFromPublicKey(masterKey.publicKey);
  //print('Bitcoin Address: $address');
}
