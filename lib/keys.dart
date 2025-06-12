import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;

import 'secp256k1.dart';
import 'utils.dart';
import 'base58.dart';

enum ScriptType {
  P2PKH, // 'Pay to Public Key Hash'
  P2SH_P2WPKH, // 'Pay to Witness Public Key Hash' wrapped in 'Pay to Script Hash'
  P2WPKH, // 'Pay to Witness Public Key Hash'
}

enum Network {
  mainnet, // Main Bitcoin network
  testnet, // Bitcoin test network
}

const _prefixDict = {
  'xprv': '0488ade4', // Mainnet - P2PKH or P2SH  - m/44'/0'
  'yprv': '049d7878', // Mainnet - P2WPKH in P2SH - m/49'/0'
  'zprv': '04b2430c', // Mainnet - P2WPKH         - m/84'/0'
  'Yprv': '0295b005', // Mainnet - Multi-signature P2WSH in P2SH
  'Zprv': '02aa7a99', // Mainnet - Multi-signature P2WSH
  'tprv': '04358394', // Testnet - P2PKH or P2SH  - m/44'/1'
  'uprv': '044a4e28', // Testnet - P2WPKH in P2SH - m/49'/1'
  'vprv': '045f18bc', // Testnet - P2WPKH         - m/84'/1'
  'Uprv': '024285b5', // Testnet - Multi-signature P2WSH in P2SH
  'Vprv': '02575048', // Testnet - Multi-signature P2WSH

  'xpub': '0488b21e', // Mainnet - P2PKH or P2SH  - m/44'/0'
  'ypub': '049d7cb2', // Mainnet - P2WPKH in P2SH - m/49'/0'
  'zpub': '04b24746', // Mainnet - P2WPKH         - m/84'/0'
  'Ypub': '0295b43f', // Mainnet - Multi-signature P2WSH in P2SH
  'Zpub': '02aa7ed3', // Mainnet - Multi-signature P2WSH
  'tpub': '043587cf', // Testnet - P2PKH or P2SH  - m/44'/1'
  'upub': '044a5262', // Testnet - P2WPKH in P2SH - m/49'/1'
  'vpub': '045f1cf6', // Testnet - P2WPKH         - m/84'/1'
  'Upub': '024289ef', // Testnet - Multi-signature P2WSH in P2SH
  'Vpub': '02575483', // Testnet - Multi-signature P2WSH
};

class PublicKey {
  int depth; // Depth in the key hierarchy, 0 for master key
  int parentFingerprint; // Fingerprint of the parent key, 0 for master key
  int childNumber; // child index of the key, 0 for master key
  // The public key and chain code
  Uint8List publicKey;
  Uint8List chainCode;
  PublicKey(
    this.depth,
    this.parentFingerprint,
    this.childNumber,
    this.publicKey,
    this.chainCode,
  );

  factory PublicKey.fromXPub(String xpub) {
    // Parse the xpub string and return a PublicKey object
    final bytes = base58Decode(xpub);
    if (bytes.length != 82) {
      throw FormatException('Invalid length: ${bytes.length}');
    }
    // check checksum
    final checksum = bytes.sublist(78, 82);
    final calculatedChecksum = hash256(bytes.sublist(0, 78)).sublist(0, 4);
    if (!listEquals(checksum, calculatedChecksum)) {
      throw FormatException('Invalid checksum');
    }
    // Extract the fields from the bytes
    final prefix = bytes.sublist(0, 4);
    final depth = bytes[4];
    final parentFingerprint = bytesToBigInt(bytes.sublist(5, 9)).toInt();
    final childNumber = bytesToBigInt(bytes.sublist(9, 13)).toInt();
    final chainCode = bytes.sublist(13, 45);
    final publicKey = bytes.sublist(45, 78);
    // Validate the prefix
    final prefixHex = bytesToHex(prefix);
    if (!_prefixDict.containsValue(prefixHex)) {
      throw FormatException('Invalid prefix: $prefixHex');
    }
    // validate the parent fingerprint
    if (depth == 0 && parentFingerprint != 0) {
      throw FormatException('Parent fingerprint must be 0 for master key');
    }
    // validate the child number
    if (depth == 0 && childNumber != 0) {
      throw FormatException('Child number must be 0 for master key');
    }
    // validate the public key prefix
    final pubkeyPrefix = publicKey[0];
    if (pubkeyPrefix != 0x02 && pubkeyPrefix != 0x03) {
      throw FormatException(
        'Invalid public key prefix: ${pubkeyPrefix.toRadixString(16).padLeft(2, '0')}',
      );
    }
    return PublicKey(
      depth,
      parentFingerprint,
      childNumber,
      publicKey,
      chainCode,
    );
  }

  static Secp256k1Point _pointFromData(Uint8List data) {
    assert(data.length == 32, 'data must be 32 bytes long');
    // Derive the point from the data using secp256k1
    final point = Secp256k1Point.generator.multiply(bytesToBigInt(data));
    return point;
  }

  Secp256k1Point _compressedPublicKeyToPoint(Uint8List publicKey) {
    // Convert a compressed public key to an integer
    if (publicKey.length != 33) {
      throw ArgumentError('Compressed public key must be 33 bytes long');
    }
    // Remove the prefix (0x02 or 0x03)
    final hex = bytesToHex(publicKey.sublist(1));
    final x = BigInt.parse(hex, radix: 16);
    return Secp256k1Point.fromX(
      x,
      publicKey[0] == 0x03 ? YParity.Odd : YParity.Even,
    ); // 0x02 means y is even, 0x03 means y is odd
  }

  int fingerprint() {
    // fingerprint is the first 4 bytes of the hash160 of the public key
    final hash = hash160(publicKey);
    return bytesToBigInt(hash.sublist(0, 4)).toInt();
  }

  PublicKey childPublicKey(int index) {
    // Check if the index is valid
    if (index < 0 || index > 0x7FFFFFFF) {
      throw ArgumentError(
        'Index ($index) must be in the range [0, 0x7FFFFFFF)',
      );
    }
    // Create a new key from the parent key and the index
    final hexData =
        bytesToHex(publicKey) + index.toRadixString(16).padLeft(8, '0');
    final data = hexToBytes(hexData); // parent pubkey + 4 byte index
    final hmac = crypto.Hmac(crypto.sha512, chainCode);
    final digest = hmac.convert(data);
    // The first 32 bytes are the child public key input, the next 32 bytes are the chain code
    final publicKeyInput = Uint8List.fromList(digest.bytes.sublist(0, 32));
    final childChainCode = Uint8List.fromList(digest.bytes.sublist(32, 64));
    // calculate the child public key
    final childPublicKeyPoint = _pointFromData(
      publicKeyInput,
    ).add(_compressedPublicKeyToPoint(publicKey));
    // compressed public key prefix: 0x02 or 0x03
    final prefix = childPublicKeyPoint.y.isEven ? '02' : '03';
    final childPublicKey = Uint8List.fromList(
      hexToBytes(
        prefix + childPublicKeyPoint.x.toRadixString(16).padLeft(64, '0'),
      ),
    );
    return PublicKey(
      depth + 1,
      fingerprint(),
      index,
      childPublicKey,
      childChainCode,
    );
  }

  String xpub(Network network, ScriptType scriptType) {
    // Return the public key in xpub format
    final prefix = switch (network) {
      Network.mainnet => switch (scriptType) {
        ScriptType.P2PKH => _prefixDict['xpub']!,
        ScriptType.P2SH_P2WPKH => _prefixDict['ypub']!,
        ScriptType.P2WPKH => _prefixDict['zpub']!,
      },
      Network.testnet => switch (scriptType) {
        ScriptType.P2PKH => _prefixDict['tpub']!,
        ScriptType.P2SH_P2WPKH => _prefixDict['upub']!,
        ScriptType.P2WPKH => _prefixDict['vpub']!,
      },
    };
    final depthHex = depth.toRadixString(16).padLeft(2, '0');
    final parentFingerprintHex = parentFingerprint
        .toRadixString(16)
        .padLeft(8, '0');
    final childNumberHex = childNumber.toRadixString(16).padLeft(8, '0');
    final chainCodeHex = bytesToHex(chainCode);
    final keyHex = bytesToHex(publicKey);
    final serialized = hexToBytes(
      '$prefix$depthHex$parentFingerprintHex$childNumberHex$chainCodeHex$keyHex',
    );
    // Calculate the checksum
    final checksum = hash256(serialized).sublist(0, 4);
    // Return the xpub in base58 format
    final xpubBytes = Uint8List.fromList(serialized + checksum);
    return base58Encode(xpubBytes);
  }
}

class PrivateKey extends PublicKey {
  Uint8List privateKey;

  PrivateKey(
    int depth,
    int parentFingerprint,
    int childNumber,
    Uint8List publicKey,
    Uint8List chainCode,
    this.privateKey,
  ) : super(depth, parentFingerprint, childNumber, publicKey, chainCode);

  static Uint8List _pubkeyFromPrivateKey(Uint8List privateKey) {
    // Derive the public key from the private key using secp256k1
    final point = PublicKey._pointFromData(privateKey);
    // Convert the point to bytes (compressed format)
    final x = point.x.toRadixString(16).padLeft(64, '0');
    // Compressed public key format: 0x02 or 0x03 + x
    final prefix = (point.y.isEven ? '02' : '03');
    return Uint8List.fromList(hexToBytes(prefix + x));
  }

  /// Derive the master key from the seed
  factory PrivateKey.fromSeed(Uint8List seed) {
    // hmac sha512 seed with 'Bitcoin seed' to get the master key
    final hmac = crypto.Hmac(crypto.sha512, utf8.encode('Bitcoin seed'));
    final digest = hmac.convert(seed);
    // The first 32 bytes are the private key, the next 32 bytes are the chain code
    final privateKey = Uint8List.fromList(digest.bytes.sublist(0, 32));
    final chainCode = Uint8List.fromList(digest.bytes.sublist(32, 64));
    // The public key is derived from the private key using secp256k1
    final publicKey = _pubkeyFromPrivateKey(privateKey);
    return PrivateKey(0, 0, 0, publicKey, chainCode, privateKey);
  }

  factory PrivateKey.fromXpriv(String xpriv) {
    // Parse the xpriv string and return a PrivateKey object
    final bytes = base58Decode(xpriv);
    if (bytes.length != 82) {
      throw FormatException('Invalid length: ${bytes.length}');
    }
    // check checksum
    final checksum = bytes.sublist(78, 82);
    final calculatedChecksum = hash256(bytes.sublist(0, 78)).sublist(0, 4);
    if (!listEquals(checksum, calculatedChecksum)) {
      throw FormatException('Invalid checksum');
    }
    // Extract the fields from the bytes
    final prefix = bytes.sublist(0, 4);
    final depth = bytes[4];
    final parentFingerprint = bytesToBigInt(bytes.sublist(5, 9)).toInt();
    final childNumber = bytesToBigInt(bytes.sublist(9, 13)).toInt();
    final chainCode = bytes.sublist(13, 45);
    final privateKeyPrefix = bytes[45];
    final privateKey = bytes.sublist(46, 78);
    // Validate the prefix
    final prefixHex = bytesToHex(prefix);
    if (!_prefixDict.containsValue(prefixHex)) {
      throw FormatException('Invalid prefix: $prefixHex');
    }
    // validate the parent fingerprint
    if (depth == 0 && parentFingerprint != 0) {
      throw FormatException('Parent fingerprint must be 0 for master key');
    }
    // validate the child number
    if (depth == 0 && childNumber != 0) {
      throw FormatException('Child number must be 0 for master key');
    }
    // validate the private key prefix
    if (privateKeyPrefix != 0x00) {
      throw FormatException(
        'Invalid private key prefix: ${privateKeyPrefix.toRadixString(16).padLeft(2, '0')}',
      );
    }
    // The public key is derived from the private key using secp256k1
    final publicKey = _pubkeyFromPrivateKey(privateKey);
    return PrivateKey(
      depth,
      parentFingerprint,
      childNumber,
      publicKey,
      chainCode,
      privateKey,
    );
  }

  PrivateKey childPrivateKey(int index, {bool hardened = true}) {
    // Check if the index is valid
    if (hardened) {
      if (index < 0x80000000 || index > 0xFFFFFFFF) {
        throw ArgumentError(
          'Index ($index) must be in the range [0x80000000, 0xFFFFFFFF)',
        );
      }
    } else if (index < 0 || index > 0x7FFFFFFF) {
      throw ArgumentError(
        'Index ($index) must be in the range [0, 0x7FFFFFFF)',
      );
    }
    // Create a new key from the master key and the index
    final data = hardened
        ? hexToBytes(
            '00' +
                bytesToHex(privateKey) +
                index.toRadixString(16).padLeft(8, '0'),
          ) // '00' + master privkey + 4 byte index
        : hexToBytes(
            bytesToHex(publicKey) + index.toRadixString(16).padLeft(8, '0'),
          ); // master pubkey + 4 byte index
    final hmac = crypto.Hmac(crypto.sha512, chainCode);
    final digest = hmac.convert(data);
    // The first 32 bytes are the child private key input, the next 32 bytes are the chain code
    final privateKeyInput = Uint8List.fromList(digest.bytes.sublist(0, 32));
    final childChainCode = Uint8List.fromList(digest.bytes.sublist(32, 64));
    // calculate the child private key
    final childPrivateKeyInt =
        (bytesToBigInt(privateKeyInput) + bytesToBigInt(privateKey)) %
        Secp256k1Point.n;
    final childPrivateKey = bigIntToBytes(childPrivateKeyInt);
    // The public key is derived from the private key using secp256k1
    final childPublicKey = _pubkeyFromPrivateKey(childPrivateKey);
    return PrivateKey(
      depth + 1,
      fingerprint(),
      index,
      childPublicKey,
      childChainCode,
      childPrivateKey,
    );
  }

  String xpriv(Network network, ScriptType scriptType) {
    // Return the private key in xpriv format
    final prefix = switch (network) {
      Network.mainnet => switch (scriptType) {
        ScriptType.P2PKH => _prefixDict['xprv']!,
        ScriptType.P2SH_P2WPKH => _prefixDict['yprv']!,
        ScriptType.P2WPKH => _prefixDict['zprv']!,
      },
      Network.testnet => switch (scriptType) {
        ScriptType.P2PKH => _prefixDict['tprv']!,
        ScriptType.P2SH_P2WPKH => _prefixDict['uprv']!,
        ScriptType.P2WPKH => _prefixDict['vprv']!,
      },
    };
    final depthHex = depth.toRadixString(16).padLeft(2, '0');
    final parentFingerprintHex = parentFingerprint
        .toRadixString(16)
        .padLeft(8, '0');
    final childNumberHex = childNumber.toRadixString(16).padLeft(8, '0');
    final chainCodeHex = bytesToHex(chainCode);
    final keyHex = '00' + bytesToHex(privateKey);
    final serialized = hexToBytes(
      '$prefix$depthHex$parentFingerprintHex$childNumberHex$chainCodeHex$keyHex',
    );
    // Calculate the checksum
    final checksum = hash256(serialized).sublist(0, 4);
    // Return the xpriv in base58 format
    final xprivBytes = Uint8List.fromList(serialized + checksum);
    return base58Encode(xprivBytes);
  }
}
