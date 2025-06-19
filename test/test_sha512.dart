// ignore_for_file: avoid_relative_lib_imports

import 'dart:convert';

import 'package:test/test.dart';

import '../lib/src/sha512.dart';
import '../lib/src/utils.dart';

void main() {
  test('sha512 test values (https://www.di-mgt.com.au/sha_testvectors.html)', () {
    expect(
      sha512(utf8.encode('')),
      equals(
        hexToBytes(
          'cf83e1357eefb8bd f1542850d66d8007 d620e4050b5715dc 83f4a921d36ce9ce 47d0d13c5d85f2b0 ff8318d2877eec2f 63b931bd47417a81 a538327af927da3e'
              .replaceAll(' ', ''),
        ),
      ),
    );
    expect(
      sha512(utf8.encode('abc')),
      equals(
        hexToBytes(
          'ddaf35a193617aba cc417349ae204131 12e6fa4e89a97ea2 0a9eeee64b55d39a 2192992a274fc1a8 36ba3c23a3feebbd 454d4423643ce80e 2a9ac94fa54ca49f'
              .replaceAll(' ', ''),
        ),
      ),
    );
    expect(
      sha512(
        utf8.encode('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'),
      ),
      equals(
        hexToBytes(
          '204a8fc6dda82f0a 0ced7beb8e08a416 57c16ef468b228a8 279be331a703c335 96fd15c13b1b07f9 aa1d3bea57789ca0 31ad85c7a71dd703 54ec631238ca3445'
              .replaceAll(' ', ''),
        ),
      ),
    );
    expect(
      sha512(
        utf8.encode(
          'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu',
        ),
      ),
      equals(
        hexToBytes(
          '8e959b75dae313da 8cf4f72814fc143f 8f7779c6eb9f7fa1 7299aeadb6889018 501d289e4900f7e4 331b99dec4b5433a c7d329eeb6dd2654 5e96e55b874be909'
              .replaceAll(' ', ''),
        ),
      ),
    );
    expect(
      sha512(utf8.encode('a' * 1000000)),
      equals(
        hexToBytes(
          'e718483d0ce76964 4e2e42c7bc15b463 8e1f98b13b204428 5632a803afa973eb de0ff244877ea60a 4cb0432ce577c31b eb009c5c2c49aa2e 4eadb217ad8cc09b'
              .replaceAll(' ', ''),
        ),
      ),
    );
  });
  test('sha512 more tests', () {
    expect(
      sha512(utf8.encode('hello world')),
      equals(
        hexToBytes(
          '309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f',
        ),
      ),
    );
    expect(
      sha512(
        utf8.encode(
          'Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.',
        ),
      ),
      equals(
        hexToBytes(
          '8ba760cac29cb2b2ce66858ead169174057aa1298ccd581514e6db6dee3285280ee6e3a54c9319071dc8165ff061d77783100d449c937ff1fb4cd1bb516a69b9',
        ),
      ),
    );
    expect(
      sha512(hexToBytes('ffffff')),
      equals(
        hexToBytes(
          '0a238ed9ee16bc4fe4a25f1145452b9bd31d7c0605d55da55bef715adae51944c7f8c2ca5ef85cc373e6304b7534168e09732d6b3a20c74f26a4d4a8e4f53d63',
        ),
      ),
    );
    expect(
      sha512(
        hexToBytes(
          'd5e3f89df30232f657246bb50d97f92e2053fcd4e37b326fe94f2c2ff67afffc320e529079ac904f2c0ff70f21129d91608b5d93e2469b28832c4e59266b2d343636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363668656c6c6f20776f726c64',
        ),
      ),
      equals(
        hexToBytes(
          '00b41ae0b8463a8741253b70a4ca7cdbe7b7fa1a100612216feab9717f8ef1f3d7a42bda7413bc68a79ee6d81ad61f1cf32b43e4ff0e5eb0af959d1b6b2dcd53',
        ),
      ),
    );
  });
}
