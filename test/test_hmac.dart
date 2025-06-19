// ignore_for_file: avoid_relative_lib_imports

import 'dart:convert';
import 'dart:typed_data';

import 'package:test/test.dart';

import '../lib/src/hmac.dart';
import '../lib/src/utils.dart';

void main() {
  late Uint8List shortKey;
  late Uint8List longKey;
  setUp(() {
    shortKey = utf8.encode('key');
    longKey = utf8.encode(
      '01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789',
    );
  });
  test('hmac sha256', () {
    expect(
      hmac(Hash.sha256, shortKey, utf8.encode('hello world')),
      equals(
        hexToBytes(
          '0ba06f1f9a6300461e43454535dc3c4223e47b1d357073d7536eae90ec095be1',
        ),
      ),
    );
    expect(
      hmac(
        Hash.sha256,
        shortKey,
        utf8.encode('The quick brown fox jumps over the lazy dog'),
      ),
      equals(
        hexToBytes(
          'f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8',
        ),
      ),
    );
    expect(
      hmac(
        Hash.sha256,
        shortKey,
        utf8.encode(
          'Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.',
        ),
      ),
      equals(
        hexToBytes(
          '8576ed2499148dcdf135702af4786f121f118a59effb2fb6fe23903a65e71a85',
        ),
      ),
    );
    expect(
      hmac(Hash.sha256, longKey, utf8.encode('hello world')),
      equals(
        hexToBytes(
          '4f709b258995703a962f222388e3896421c1d18023db20ed939782d848155c1f',
        ),
      ),
    );
    expect(
      hmac(
        Hash.sha256,
        longKey,
        utf8.encode('The quick brown fox jumps over the lazy dog'),
      ),
      equals(
        hexToBytes(
          '9849a54221133936968479b80b73f26e2d6a45e9fa1abda0cc4fff9656014f2f',
        ),
      ),
    );
  });
  test('hmac sha512', () {
    expect(
      hmac(Hash.sha512, shortKey, utf8.encode('hello world')),
      equals(
        hexToBytes(
          'ea0625a5ff1cd1653a327f8a4ae2f478fc51405c73ddac3a8a05a7a810310a6a14d7c8b4d284013493a6016ecadc772cfd98ed6cbe745949c5e6119fafb63b54',
        ),
      ),
    );
    expect(
      hmac(
        Hash.sha512,
        shortKey,
        utf8.encode('The quick brown fox jumps over the lazy dog'),
      ),
      equals(
        hexToBytes(
          'b42af09057bac1e2d41708e48a902e09b5ff7f12ab428a4fe86653c73dd248fb82f948a549f7b791a5b41915ee4d1ec3935357e4e2317250d0372afa2ebeeb3a',
        ),
      ),
    );
    expect(
      hmac(
        Hash.sha512,
        shortKey,
        utf8.encode(
          'Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.',
        ),
      ),
      equals(
        hexToBytes(
          'e467d7828f85bc802daaa2b39c25d9f1774be0aea4e75c9536dc8a676fffdb91d204a96e02eefa4f8abf897b08830aa87331ea289d86dbec08b5302b99bd55af',
        ),
      ),
    );
    expect(
      hmac(Hash.sha512, longKey, utf8.encode('hello world')),
      equals(
        hexToBytes(
          '07b0c0a730f0727024aa99ee61a8c626d3c1fa07a2f54df3f0482087fac15815d3195862978391d89127b34a60949275cc2918ee6a4176dffdf13cdb1650ace4',
        ),
      ),
    );
    expect(
      hmac(
        Hash.sha512,
        longKey,
        utf8.encode('The quick brown fox jumps over the lazy dog'),
      ),
      equals(
        hexToBytes(
          'a1f6e06f44e517b01c6f7cd16ee39717c6fb7107de6e2c99bb23ef9a5bb488fa9389ea5ad7c6a1310ddcabf753ad3c82e7bae5a38cde8546ebf289fcece6d464',
        ),
      ),
    );
  });
}
