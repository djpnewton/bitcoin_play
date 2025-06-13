import 'dart:typed_data';

enum Network {
  mainnet, // Main Bitcoin network
  testnet, // Bitcoin test network
  regtest, // Bitcoin regression test network
}

enum ScriptType {
  p2pkh, // 'Pay to Public Key Hash'
  p2shP2wpkh, // 'Pay to Witness Public Key Hash' wrapped in 'Pay to Script Hash'
  p2wpkh, // 'Pay to Witness Public Key Hash'
}

bool isValidCompressedPublicKey(Uint8List publicKey) {
  // Check if the public key is a valid compressed format
  return publicKey.length == 33 &&
      (publicKey[0] == 0x02 || publicKey[0] == 0x03);
}

bool isValidPublicKey(Uint8List publicKey) {
  // Check if the public key is a valid compressed or uncompressed format
  if (isValidCompressedPublicKey(publicKey)) {
    // Compressed public key
    return true;
  } else if (publicKey.length == 65) {
    // Uncompressed public key
    return publicKey[0] == 0x04;
  }
  return false;
}
