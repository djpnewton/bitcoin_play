// ignore_for_file: avoid_relative_lib_imports

import 'dart:typed_data';

import 'package:benchmark_runner/benchmark_runner.dart';

import '../lib/src/utils.dart';
import '../lib/src/ripemd160.dart';
import '../lib/src/sha256.dart';
import '../lib/src/secp256k1.dart';
import '../lib/src/keys.dart';

void main() {
  group('Ripemd160', () {
    var data = Uint8List.fromList(List.generate(1000, (index) => index % 256));
    benchmark('1000 bytes values 0->255', () {
      ripemd160(data);
    });
    data = Uint8List.fromList(List.filled(1000, 0));
    benchmark('1000 bytes all zeros', () {
      ripemd160(data);
    });
    data = Uint8List.fromList(List.filled(1000, 255));
    benchmark('1000 bytes all 255', () {
      ripemd160(data);
    });
  });
  group('Sha256', () {
    var data = Uint8List.fromList(List.generate(1000, (index) => index % 256));
    benchmark('1000 bytes values 0->255', () {
      sha256(data);
    });
    data = Uint8List.fromList(List.filled(1000, 0));
    benchmark('1000 bytes all zeros', () {
      sha256(data);
    });
    data = Uint8List.fromList(List.filled(1000, 255));
    benchmark('1000 bytes all 255', () {
      sha256(data);
    });
  });
  group('secp256k1', () {
    benchmark('multiply generator by 0xffff', () {
      Secp256k1Point.generator.multiply(BigInt.from(0xffff));
    });
    benchmark('multiply generator by N', () {
      Secp256k1Point.generator.multiply(Secp256k1Point.n);
    });
  });
  group('keys', () {
    var privateKey = hexToBytes(
      'ff00000000000000000000000000000000000000000000000000000000000000',
    );
    benchmark('public key from "ff0000.."', () {
      PrivateKey.pubkeyFromPrivateKey(privateKey);
    });
    privateKey = hexToBytes(
      '00000000000000000000000000000000000000000000000000000000000000ff',
    );
    benchmark('public key from "..0000ff"', () {
      PrivateKey.pubkeyFromPrivateKey(privateKey);
    });
    privateKey = hexToBytes(
      'dfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
    );
    benchmark('public key from "dfffff.."', () {
      PrivateKey.pubkeyFromPrivateKey(privateKey);
    });
  });
}
