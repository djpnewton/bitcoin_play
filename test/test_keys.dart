import 'dart:typed_data';

import 'package:bip39/bip39.dart';
import 'package:test/test.dart';

import '../lib/keys.dart';
import '../lib/utils.dart';

void main() {
  late Uint8List seed;
  setUp(() async {
    seed = mnemonicToSeed(
      'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
    );
  });
  tearDown(() async {});
  test('PrivateKey.fromSeed() generates master key from seed', () {
    var masterKey = PrivateKey.fromSeed(seed);
    expect(masterKey.depth, equals(0));
    expect(masterKey.parentFingerprint, equals(0));
    expect(masterKey.childNumber, equals(0));
    expect(
      masterKey.privateKey,
      equals(
        hexToBytes(
          '1837c1be8e2995ec11cda2b066151be2cfb48adf9e47b151d46adab3a21cdf67',
        ),
      ),
    );
    expect(
      masterKey.publicKey,
      equals(
        hexToBytes(
          '03d902f35f560e0470c63313c7369168d9d7df2d49bf295fd9fb7cb109ccee0494',
        ),
      ),
    ); // prefix 03
    expect(
      masterKey.chainCode,
      equals(
        hexToBytes(
          '7923408dadd3c7b56eed15567707ae5e5dca089de972e07f3b860450e2a3b70e',
        ),
      ),
    );
    masterKey = PrivateKey.fromSeed(
      hexToBytes(
        '303d8e4e4a7d18f14a8296b5941648ceca152f01d3515e78f77f91e69f20f2b3fa41eb9f29a7e9ac99daff45131aa5779808fdad586ff9edf9e29d6dc65794bc',
      ),
    );
    expect(masterKey.depth, equals(0));
    expect(masterKey.parentFingerprint, equals(0));
    expect(masterKey.childNumber, equals(0));
    expect(
      masterKey.privateKey,
      equals(
        hexToBytes(
          '74a9b945736cd9d064a8263b94a3e4f412aadc6bd59d1b9ab62b170c2739a1a6',
        ),
      ),
    );
    expect(
      masterKey.publicKey,
      equals(
        hexToBytes(
          '0260fea076bb2f4e075c4c497f14fce46b404af5eedcb7e0f03f8f4ae06b0a3316',
        ),
      ),
    ); // prefix 02
    expect(
      masterKey.chainCode,
      equals(
        hexToBytes(
          '2706f1f9292cbf818d99185689379175a84c4faf8441b490410b9a1570b358f5',
        ),
      ),
    );
  });
  test('PublicKey.childPublicKey() generates child public key', () {
    var masterKey = PrivateKey.fromSeed(seed);
    // m/0
    var childKey = masterKey.childPublicKey(0);
    expect(childKey.depth, equals(1));
    expect(childKey.parentFingerprint, equals(masterKey.fingerprint()));
    expect(childKey.childNumber, equals(0));
    expect(
      childKey.publicKey,
      equals(
        hexToBytes(
          '0376bf533d4b15510fa9f4124b6e48616f07debcf2ef0cfb185cdc4a576450b475',
        ),
      ),
    );
    expect(
      childKey.chainCode,
      equals(
        hexToBytes(
          'e0e6503ac057cf5dc76e0735e56dd44d193b2e9e271cc2d46bc759c99b021e3c',
        ),
      ),
    );
    expect(() => masterKey.childPublicKey(0x80000000), throwsArgumentError);
    expect(() => masterKey.childPublicKey(-1), throwsArgumentError);
    // m/1
    childKey = masterKey.childPublicKey(1);
    expect(childKey.depth, equals(1));
    expect(childKey.parentFingerprint, equals(masterKey.fingerprint()));
    expect(childKey.childNumber, equals(1));
    expect(
      childKey.publicKey,
      equals(
        hexToBytes(
          '02ea2649b3512b9a859ab658a85e2989a7ae39b2518877b2dc0f2b44b785d5788d',
        ),
      ),
    );
    expect(
      childKey.chainCode,
      equals(
        hexToBytes(
          '5c48917d6838b666aeb11eac7c4f98f807779b57c7522e38509719eeb1e7a592',
        ),
      ),
    );
    // argument error for invalid child number
    expect(() => masterKey.childPublicKey(0x80000000), throwsArgumentError);
    expect(() => masterKey.childPublicKey(-1), throwsArgumentError);
  });
  test('PrivateKey.childPrivateKey() generates child private key', () {
    var masterKey = PrivateKey.fromSeed(seed);
    //TODO

    // argument error for invalid child number
    expect(
      () => masterKey.childPrivateKey(0x7FFFFFFF, hardened: true),
      throwsArgumentError,
    );
    expect(
      () => masterKey.childPrivateKey(0xFFFFFFFF01, hardened: true),
      throwsArgumentError,
    );
    expect(
      () => masterKey.childPrivateKey(-1, hardened: false),
      throwsArgumentError,
    );
    expect(
      () => masterKey.childPrivateKey(0xFFFFFFFF, hardened: false),
      throwsArgumentError,
    );
  });
  test('PublicKey.xpub()', () {
    //TODO
  });
  test('PublicKey.fromXPub()', () {
    //TODO
  });
  test('PrivateKey.xpriv()', () {
    //TODO
  });
  test('PrivateKey.fromXPriv()', () {
    //TODO
  });
}
