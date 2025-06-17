// ignore_for_file: avoid_relative_lib_imports

import 'dart:convert';

import 'package:test/test.dart';

import '../lib/src/ripemd160.dart';
import '../lib/src/utils.dart';

void main() {
  test('ripemd160', () {
    expect(
      ripemd160(hexToBytes('')),
      equals(hexToBytes('9c1185a5c5e9fc54612808977ee8f548b2258d31')),
    );
    expect(
      ripemd160(utf8.encode('a')),
      equals(hexToBytes('0bdc9d2d256b3ee9daae347be6f4dc835a467ffe')),
    );
    expect(
      ripemd160(utf8.encode('abc')),
      equals(hexToBytes('8eb208f7e05d987a9b044a8e98c6b087f15a0bfc')),
    );
    expect(
      ripemd160(utf8.encode('message digest')),
      equals(hexToBytes('5d0689ef49d2fae572b881b123a85ffa21595f36')),
    );
    expect(
      ripemd160(utf8.encode('abcdefghijklmnopqrstuvwxyz')),
      equals(hexToBytes('f71c27109c692c1b56bbdceb5b9d2865b3708dbc')),
    );
    expect(
      ripemd160(
        utf8.encode('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'),
      ),
      equals(hexToBytes('12a053384a9c0c88e405a06c27dcf49ada62eb2b')),
    );
    expect(
      ripemd160(
        utf8.encode(
          'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
        ),
      ),
      equals(hexToBytes('b0e20b6e3116640286ed3a87a5713079b21f5189')),
    );
    expect(
      ripemd160(utf8.encode('1234567890' * 8)),
      equals(hexToBytes('9b752e45573d4b39f4dbd3323cab82bf63326bfb')),
    );
    expect(
      ripemd160(utf8.encode('a' * 1000000)),
      equals(hexToBytes('52783243c1697bdbe16d37f97f68f08325dc1528')),
    );
  });
}
