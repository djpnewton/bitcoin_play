// ignore_for_file: avoid_relative_lib_imports

import 'dart:typed_data';

import 'package:test/test.dart';

import '../lib/src/keys.dart';
import '../lib/src/utils.dart';
import '../lib/src/common.dart';
import '../lib/src/wif.dart';
import '../lib/src/base58.dart';
import '../lib/src/mnemonic.dart';

void main() {
  late String seed;
  late PrivateKey masterKey;
  setUp(() {
    seed = mnemonicToSeed(
      'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
    );
    masterKey = PrivateKey.fromSeed(hexToBytes(seed));
  });
  tearDown(() {});
  test('PrivateKey.fromSeed() generates master key from seed', () {
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
    // m/0
    var childKey = masterKey.childPrivateKey(0, hardened: false);
    expect(childKey.depth, equals(1));
    expect(childKey.parentFingerprint, equals(masterKey.fingerprint()));
    expect(childKey.childNumber, equals(0));
    expect(
      childKey.privateKey,
      equals(
        hexToBytes(
          'baa89a8bdd61c5e22b9f10601d8791c9f8fc4b2fa6df9d68d336f0eb03b06eb6',
        ),
      ),
    );
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
    // m/0'
    childKey = masterKey.childPrivateKey(0x80000000, hardened: true);
    expect(childKey.depth, equals(1));
    expect(childKey.parentFingerprint, equals(masterKey.fingerprint()));
    expect(childKey.childNumber, equals(0x80000000));
    expect(
      childKey.privateKey,
      equals(
        hexToBytes(
          'c08cf331996482c06db3d259ff99be4bf7083824d53185e33191ee7ceb2bf96f',
        ),
      ),
    );
    expect(
      childKey.publicKey,
      equals(
        hexToBytes(
          '027f1d87730e460e921b382242911565bf93daf2081ed685b2edd1d01176b2c13c',
        ),
      ),
    );
    expect(
      childKey.chainCode,
      equals(
        hexToBytes(
          'f1c03f5ff97108912fd56761d3fada8879e4173aba45f10da4bbd94b1c497160',
        ),
      ),
    );
    // m/1
    childKey = masterKey.childPrivateKey(1, hardened: false);
    expect(childKey.depth, equals(1));
    expect(childKey.parentFingerprint, equals(masterKey.fingerprint()));
    expect(childKey.childNumber, equals(1));
    expect(
      childKey.privateKey,
      equals(
        hexToBytes(
          'c1beaff0c4db984670a40c69c2947b9d33cd7f6e749c67e1fcb5c6118dda1282',
        ),
      ),
    );
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
    // m/1'
    childKey = masterKey.childPrivateKey(0x80000001, hardened: true);
    expect(childKey.depth, equals(1));
    expect(childKey.parentFingerprint, equals(masterKey.fingerprint()));
    expect(childKey.childNumber, equals(0x80000001));
    expect(
      childKey.privateKey,
      equals(
        hexToBytes(
          '3ef02fc53000742891fc90458ba9edc8363d8f1f267e326b1078710c7db34de5',
        ),
      ),
    );
    expect(
      childKey.publicKey,
      equals(
        hexToBytes(
          '03b5184a526dac6abda3d8d54a541471ce83e8c2260d56706053e2780922319f5e',
        ),
      ),
    );
    expect(
      childKey.chainCode,
      equals(
        hexToBytes(
          '43cc4bca59c666a5f79265148125802ed2cec46df1c5ca8e6a058dab525a73f1',
        ),
      ),
    );
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
  test('bip32 test vector 1', () {
    var seed = hexToBytes('000102030405060708090a0b0c0d0e0f');
    var masterKey = PrivateKey.fromSeed(seed);
    expect(
      masterKey.xpub(),
      equals(
        'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8',
      ),
    );
    expect(
      masterKey.xprv(),
      equals(
        'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi',
      ),
    );
    var childKey = masterKey.childFromDerivationPath('m/0h');
    expect(
      childKey.xpub(),
      equals(
        'xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw',
      ),
    );
    expect(
      childKey.xprv(),
      equals(
        'xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7',
      ),
    );
    var childPubKey = masterKey.childFromDerivationPath('m/0h/1');
    expect(
      childPubKey.xpub(),
      equals(
        'xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ',
      ),
    );
    expect(
      childPubKey.xprv(),
      equals(
        'xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs',
      ),
    );
    childPubKey = masterKey.childFromDerivationPath('m/0h/1/2h');
    expect(
      childPubKey.xpub(),
      equals(
        'xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5',
      ),
    );
    expect(
      childPubKey.xprv(),
      equals(
        'xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM',
      ),
    );
    childPubKey = masterKey.childFromDerivationPath('m/0h/1/2h/2');
    expect(
      childPubKey.xpub(),
      equals(
        'xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV',
      ),
    );
    expect(
      childPubKey.xprv(),
      equals(
        'xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334',
      ),
    );
    childPubKey = masterKey.childFromDerivationPath('m/0h/1/2h/2/1000000000');
    expect(
      childPubKey.xpub(),
      equals(
        'xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy',
      ),
    );
    expect(
      childPubKey.xprv(),
      equals(
        'xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76',
      ),
    );
  });
  test('bip32 test vector 2', () {
    masterKey = PrivateKey.fromSeed(
      hexToBytes(
        'fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542',
      ),
    );
    expect(
      masterKey.xpub(),
      equals(
        'xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB',
      ),
    );
    expect(
      masterKey.xprv(),
      equals(
        'xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U',
      ),
    );
    var childKey = masterKey.childFromDerivationPath('m/0');
    expect(
      childKey.xpub(),
      equals(
        'xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH',
      ),
    );
    expect(
      childKey.xprv(),
      equals(
        'xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt',
      ),
    );
    childKey = masterKey.childFromDerivationPath('m/0/2147483647H');
    expect(
      childKey.xpub(),
      equals(
        'xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a',
      ),
    );
    expect(
      childKey.xprv(),
      equals(
        'xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9',
      ),
    );
    childKey = masterKey.childFromDerivationPath('m/0/2147483647H/1');
    expect(
      childKey.xpub(),
      equals(
        'xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon',
      ),
    );
    expect(
      childKey.xprv(),
      equals(
        'xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef',
      ),
    );
    childKey = masterKey.childFromDerivationPath(
      'm/0/2147483647H/1/2147483646H',
    );
    expect(
      childKey.xpub(),
      equals(
        'xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL',
      ),
    );
    expect(
      childKey.xprv(),
      equals(
        'xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc',
      ),
    );
    childKey = masterKey.childFromDerivationPath(
      'm/0/2147483647H/1/2147483646H/2',
    );
    expect(
      childKey.xpub(),
      equals(
        'xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt',
      ),
    );
    expect(
      childKey.xprv(),
      equals(
        'xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j',
      ),
    );
  });
  test('bip32 test vector 3', () {
    // These vectors test for the retention of leading zeros. See (at github) bitpay/bitcore-lib#47 and iancoleman/bip39#58 for more information.
    masterKey = PrivateKey.fromSeed(
      hexToBytes(
        '4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be',
      ),
    );
    expect(
      masterKey.xpub(),
      equals(
        'xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13',
      ),
    );
    expect(
      masterKey.xprv(),
      equals(
        'xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6',
      ),
    );
    var childKey = masterKey.childFromDerivationPath('m/0h');
    expect(
      childKey.xpub(),
      equals(
        'xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y',
      ),
    );
    expect(
      childKey.xprv(),
      equals(
        'xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L',
      ),
    );
  });
  test('bip32 test vector 4', () {
    // These vectors test for the retention of leading zeros. See (at github) btcsuite/btcutil#172 for more information.
    masterKey = PrivateKey.fromSeed(
      hexToBytes(
        '3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678',
      ),
    );
    expect(
      masterKey.xpub(),
      equals(
        'xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUKJyuyu5F1rzYGVxyL6tmgBUAEPrEz92mBXjByMRiJdba9wpnN37RLLAXa',
      ),
    );
    expect(
      masterKey.xprv(),
      equals(
        'xprv9s21ZrQH143K48vGoLGRPxgo2JNkJ3J3fqkirQC2zVdk5Dgd5w14S7fRDyHH4dWNHUgkvsvNDCkvAwcSHNAQwhwgNMgZhLtQC63zxwhQmRv',
      ),
    );
    var childKey = masterKey.childFromDerivationPath('m/0h');
    expect(
      childKey.xpub(),
      equals(
        'xpub69AUMk3qDBi3uW1sXgjCmVjJ2G6WQoYSnNHyzkmdCHEhSZ4tBok37xfFEqHd2AddP56Tqp4o56AePAgCjYdvpW2PU2jbUPFKsav5ut6Ch1m',
      ),
    );
    expect(
      childKey.xprv(),
      equals(
        'xprv9vB7xEWwNp9kh1wQRfCCQMnZUEG21LpbR9NPCNN1dwhiZkjjeGRnaALmPXCX7SgjFTiCTT6bXes17boXtjq3xLpcDjzEuGLQBM5ohqkao9G',
      ),
    );
    childKey = masterKey.childFromDerivationPath('m/0h/1h');
    expect(
      childKey.xpub(),
      equals(
        'xpub6BJA1jSqiukeaesWfxe6sNK9CCGaujFFSJLomWHprUL9DePQ4JDkM5d88n49sMGJxrhpjazuXYWdMf17C9T5XnxkopaeS7jGk1GyyVziaMt',
      ),
    );
    expect(
      childKey.xprv(),
      equals(
        'xprv9xJocDuwtYCMNAo3Zw76WENQeAS6WGXQ55RCy7tDJ8oALr4FWkuVoHJeHVAcAqiZLE7Je3vZJHxspZdFHfnBEjHqU5hG1Jaj32dVoS6XLT1',
      ),
    );
  });
  test('bip32 test vector 5', () {
    // These vectors test that invalid extended keys are recognized as invalid.
    // pubkey version / prvkey mismatch
    expect(
      () => PublicKey.fromXPub(
        'xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6LBpB85b3D2yc8sfvZU521AAwdZafEz7mnzBBsz4wKY5fTtTQBm',
      ),
      throwsFormatException,
    );
    // prvkey version / pubkey mismatch
    expect(
      () => PrivateKey.fromXPrv(
        'xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFGTQQD3dC4H2D5GBj7vWvSQaaBv5cxi9gafk7NF3pnBju6dwKvH',
      ),
      throwsFormatException,
    );
    // invalid pubkey prefix 04
    expect(
      () => PublicKey.fromXPub(
        'xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Txnt3siSujt9RCVYsx4qHZGc62TG4McvMGcAUjeuwZdduYEvFn',
      ),
      throwsFormatException,
    );
    // invalid prvkey prefix 04
    expect(
      () => PrivateKey.fromXPrv(
        'xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFGpWnsj83BHtEy5Zt8CcDr1UiRXuWCmTQLxEK9vbz5gPstX92JQ',
      ),
      throwsFormatException,
    );
    // invalid pubkey prefix 01
    expect(
      () => PublicKey.fromXPub(
        'xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6N8ZMMXctdiCjxTNq964yKkwrkBJJwpzZS4HS2fxvyYUA4q2Xe4',
      ),
      throwsFormatException,
    );
    // invalid prvkey prefix 01
    expect(
      () => PrivateKey.fromXPrv(
        'xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD9y5gkZ6Eq3Rjuahrv17fEQ3Qen6J',
      ),
      throwsFormatException,
    );
    // zero depth with non-zero parent fingerprint
    expect(
      () => PrivateKey.fromXPrv(
        'xprv9s2SPatNQ9Vc6GTbVMFPFo7jsaZySyzk7L8n2uqKXJen3KUmvQNTuLh3fhZMBoG3G4ZW1N2kZuHEPY53qmbZzCHshoQnNf4GvELZfqTUrcv',
      ),
      throwsFormatException,
    );
    // zero depth with non-zero parent fingerprint
    expect(
      () => PublicKey.fromXPub(
        'xpub661no6RGEX3uJkY4bNnPcw4URcQTrSibUZ4NqJEw5eBkv7ovTwgiT91XX27VbEXGENhYRCf7hyEbWrR3FewATdCEebj6znwMfQkhRYHRLpJ',
      ),
      throwsFormatException,
    );
    // zero depth with non-zero index
    expect(
      () => PrivateKey.fromXPrv(
        'xprv9s21ZrQH4r4TsiLvyLXqM9P7k1K3EYhA1kkD6xuquB5i39AU8KF42acDyL3qsDbU9NmZn6MsGSUYZEsuoePmjzsB3eFKSUEh3Gu1N3cqVUN',
      ),
      throwsFormatException,
    );
    // zero depth with non-zero index
    expect(
      () => PublicKey.fromXPub(
        'xpub661MyMwAuDcm6CRQ5N4qiHKrJ39Xe1R1NyfouMKTTWcguwVcfrZJaNvhpebzGerh7gucBvzEQWRugZDuDXjNDRmXzSZe4c7mnTK97pTvGS8',
      ),
      throwsFormatException,
    );
    // unknown extended key version
    expect(
      () => PublicKey.fromXPub(
        'DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHGMQzT7ayAmfo4z3gY5KfbrZWZ6St24UVf2Qgo6oujFktLHdHY4',
      ),
      throwsArgumentError,
    );
    expect(
      () => PrivateKey.fromXPrv(
        'DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHGMQzT7ayAmfo4z3gY5KfbrZWZ6St24UVf2Qgo6oujFktLHdHY4',
      ),
      throwsArgumentError,
    );
    // unknown extended key version
    expect(
      () => PublicKey.fromXPub(
        'DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHPmHJiEDXkTiJTVV9rHEBUem2mwVbbNfvT2MTcAqj3nesx8uBf9',
      ),
      throwsArgumentError,
    );
    expect(
      () => PrivateKey.fromXPrv(
        'DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHPmHJiEDXkTiJTVV9rHEBUem2mwVbbNfvT2MTcAqj3nesx8uBf9',
      ),
      throwsArgumentError,
    );
    // private key 0 not in 1..n-1
    expect(
      () => PrivateKey.fromXPrv(
        'xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzF93Y5wvzdUayhgkkFoicQZcP3y52uPPxFnfoLZB21Teqt1VvEHx',
      ),
      throwsFormatException,
    );
    // private key n not in 1..n-1
    expect(
      () => PrivateKey.fromXPrv(
        'xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD5SDKr24z3aiUvKr9bJpdrcLg1y3G',
      ),
      throwsFormatException,
    );
    // invalid pubkey 020000000000000000000000000000000000000000000000000000000000000007
    expect(
      () => PublicKey.fromXPub(
        'xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Q5JXayek4PRsn35jii4veMimro1xefsM58PgBMrvdYre8QyULY',
      ),
      throwsFormatException,
    );
    // invalid checksum
    expect(
      () => PrivateKey.fromXPrv(
        'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHL',
      ),
      throwsFormatException,
    );
  });
  test('bip49 test vectors', () {
    expect(
      masterKey.xprv(
        network: Network.testnet,
        scriptType: ScriptType.p2shP2wpkh,
      ),
      equals(
        'uprv8tXDerPXZ1QsVNjUJWTurs9kA1KGfKUAts74GCkcXtU8GwnH33GDRbNJpEqTvipfCyycARtQJhmdfWf8oKt41X9LL1zeD2pLsWmxEk3VAwd',
      ),
    );
    // Account 0, root = m/49'/1'/0'
    var childKey = masterKey.childFromDerivationPath('m/49h/1h/0h');
    expect(
      childKey.xprv(
        network: Network.testnet,
        scriptType: ScriptType.p2shP2wpkh,
      ),
      equals(
        'uprv91G7gZkzehuMVxDJTYE6tLivdF8e4rvzSu1LFfKw3b2Qx1Aj8vpoFnHdfUZ3hmi9jsvPifmZ24RTN2KhwB8BfMLTVqaBReibyaFFcTP1s9n',
      ),
    );
    expect(
      childKey.xpub(
        network: Network.testnet,
        scriptType: ScriptType.p2shP2wpkh,
      ),
      equals(
        'upub5EFU65HtV5TeiSHmZZm7FUffBGy8UKeqp7vw43jYbvZPpoVsgU93oac7Wk3u6moKegAEWtGNF8DehrnHtv21XXEMYRUocHqguyjknFHYfgY',
      ),
    );
    // Account 0, first receiving private key = m/49'/1'/0'/0/0
    childKey = masterKey.childFromDerivationPath('m/49h/1h/0h/0/0');
    var wif = Wif(Network.testnet, childKey.privateKey, true);
    expect(
      wif.toWifString(),
      equals('cULrpoZGXiuC19Uhvykx7NugygA3k86b3hmdCeyvHYQZSxojGyXJ'),
    );
    expect(
      childKey.privateKey,
      equals(
        hexToBytes(
          '0xc9bdb49cfbaedca21c4b1f3a7803c34636b1d7dc55a717132443fc3f4c5867e8',
        ),
      ),
    );
    expect(
      childKey.publicKey,
      equals(
        hexToBytes(
          '0x03a1af804ac108a8a51782198c2d034b28bf90c8803f5a53f76276fa69a4eae77f',
        ),
      ),
    );
    // Address derivation
    final keyhash = hash160(childKey.publicKey);
    expect(
      keyhash,
      equals(hexToBytes('0x38971f73930f6c141d977ac4fd4a727c854935b3')),
    );
    final scriptSig = Uint8List.fromList([0, 20] + keyhash);
    final scriptHash = hash160(scriptSig);
    expect(
      scriptHash,
      equals(hexToBytes('0x336caa13e08b96080a32b5d818d59b4ab3b36742')),
    );
    final address = childKey.address(
      scriptType: ScriptType.p2shP2wpkh,
      network: Network.testnet,
    );
    expect(address, equals('2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2'));
    final addressBytes = base58DecodeCheck(address).sublist(1); // Skip prefix
    expect(addressBytes, equals(scriptHash));
  });
  test('bip84 test vectors', () {
    expect(
      masterKey.xprv(scriptType: ScriptType.p2wpkh),
      equals(
        'zprvAWgYBBk7JR8Gjrh4UJQ2uJdG1r3WNRRfURiABBE3RvMXYSrRJL62XuezvGdPvG6GFBZduosCc1YP5wixPox7zhZLfiUm8aunE96BBa4Kei5',
      ),
    );
    expect(
      masterKey.xpub(scriptType: ScriptType.p2wpkh),
      equals(
        'zpub6jftahH18ngZxLmXaKw3GSZzZsszmt9WqedkyZdezFtWRFBZqsQH5hyUmb4pCEeZGmVfQuP5bedXTB8is6fTv19U1GQRyQUKQGUTzyHACMF',
      ),
    );
    // Account 0, root = m/84'/0'/0'
    var childKey = masterKey.childFromDerivationPath('m/84h/0h/0h');
    expect(
      childKey.xprv(scriptType: ScriptType.p2wpkh),
      equals(
        'zprvAdG4iTXWBoARxkkzNpNh8r6Qag3irQB8PzEMkAFeTRXxHpbF9z4QgEvBRmfvqWvGp42t42nvgGpNgYSJA9iefm1yYNZKEm7z6qUWCroSQnE',
      ),
    );
    expect(
      childKey.xpub(scriptType: ScriptType.p2wpkh),
      equals(
        'zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs',
      ),
    );
    // Account 0, first receiving private key = m/84'/0'/0'/0/0
    childKey = masterKey.childFromDerivationPath('m/84h/0h/0h/0/0');
    var wif = Wif(Network.mainnet, childKey.privateKey, true);
    expect(
      wif.toWifString(),
      equals('KyZpNDKnfs94vbrwhJneDi77V6jF64PWPF8x5cdJb8ifgg2DUc9d'),
    );
    expect(
      childKey.publicKey,
      equals(
        hexToBytes(
          '0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c',
        ),
      ),
    );
    expect(
      childKey.address(scriptType: ScriptType.p2wpkh, network: Network.mainnet),
      equals('bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu'),
    );
    // Account 0, second receiving address = m/84'/0'/0'/0/1
    childKey = masterKey.childFromDerivationPath('m/84h/0h/0h/0/1');
    wif = Wif(Network.mainnet, childKey.privateKey, true);
    expect(
      wif.toWifString(),
      equals('Kxpf5b8p3qX56DKEe5NqWbNUP9MnqoRFzZwHRtsFqhzuvUJsYZCy'),
    );
    expect(
      childKey.publicKey,
      equals(
        hexToBytes(
          '03e775fd51f0dfb8cd865d9ff1cca2a158cf651fe997fdc9fee9c1d3b5e995ea77',
        ),
      ),
    );
    expect(
      childKey.address(scriptType: ScriptType.p2wpkh, network: Network.mainnet),
      equals('bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g'),
    );
    // Account 0, first change address = m/84'/0'/0'/1/0
    childKey = masterKey.childFromDerivationPath('m/84h/0h/0h/1/0');
    wif = Wif(Network.mainnet, childKey.privateKey, true);
    expect(
      wif.toWifString(),
      equals('KxuoxufJL5csa1Wieb2kp29VNdn92Us8CoaUG3aGtPtcF3AzeXvF'),
    );
    expect(
      childKey.publicKey,
      equals(
        hexToBytes(
          '03025324888e429ab8e3dbaf1f7802648b9cd01e9b418485c5fa4c1b9b5700e1a6',
        ),
      ),
    );
    expect(
      childKey.address(scriptType: ScriptType.p2wpkh, network: Network.mainnet),
      equals('bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el'),
    );
  });
}
