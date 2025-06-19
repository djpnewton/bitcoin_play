import 'dart:typed_data';

import 'package:dartcoin/dartcoin.dart';

class State {
  BigInt h0;
  BigInt h1;
  BigInt h2;
  BigInt h3;
  BigInt h4;
  BigInt h5;
  BigInt h6;
  BigInt h7;
  State(this.h0, this.h1, this.h2, this.h3, this.h4, this.h5, this.h6, this.h7);
  State clone() {
    return State(h0, h1, h2, h3, h4, h5, h6, h7);
  }
}

final BigInt _maxInt64 = BigInt.parse('FFFFFFFFFFFFFFFF', radix: 16);

// dart format off
final _k = [
    BigInt.parse('428a2f98d728ae22', radix: 16), BigInt.parse('7137449123ef65cd', radix: 16), BigInt.parse('b5c0fbcfec4d3b2f', radix: 16),
    BigInt.parse('e9b5dba58189dbbc', radix: 16), BigInt.parse('3956c25bf348b538', radix: 16), BigInt.parse('59f111f1b605d019', radix: 16),
    BigInt.parse('923f82a4af194f9b', radix: 16), BigInt.parse('ab1c5ed5da6d8118', radix: 16), BigInt.parse('d807aa98a3030242', radix: 16),
    BigInt.parse('12835b0145706fbe', radix: 16), BigInt.parse('243185be4ee4b28c', radix: 16), BigInt.parse('550c7dc3d5ffb4e2', radix: 16),
    BigInt.parse('72be5d74f27b896f', radix: 16), BigInt.parse('80deb1fe3b1696b1', radix: 16), BigInt.parse('9bdc06a725c71235', radix: 16),
    BigInt.parse('c19bf174cf692694', radix: 16), BigInt.parse('e49b69c19ef14ad2', radix: 16), BigInt.parse('efbe4786384f25e3', radix: 16),
    BigInt.parse('0fc19dc68b8cd5b5', radix: 16), BigInt.parse('240ca1cc77ac9c65', radix: 16), BigInt.parse('2de92c6f592b0275', radix: 16),
    BigInt.parse('4a7484aa6ea6e483', radix: 16), BigInt.parse('5cb0a9dcbd41fbd4', radix: 16), BigInt.parse('76f988da831153b5', radix: 16),
    BigInt.parse('983e5152ee66dfab', radix: 16), BigInt.parse('a831c66d2db43210', radix: 16), BigInt.parse('b00327c898fb213f', radix: 16),
    BigInt.parse('bf597fc7beef0ee4', radix: 16), BigInt.parse('c6e00bf33da88fc2', radix: 16), BigInt.parse('d5a79147930aa725', radix: 16),
    BigInt.parse('06ca6351e003826f', radix: 16), BigInt.parse('142929670a0e6e70', radix: 16), BigInt.parse('27b70a8546d22ffc', radix: 16),
    BigInt.parse('2e1b21385c26c926', radix: 16), BigInt.parse('4d2c6dfc5ac42aed', radix: 16), BigInt.parse('53380d139d95b3df', radix: 16),
    BigInt.parse('650a73548baf63de', radix: 16), BigInt.parse('766a0abb3c77b2a8', radix: 16), BigInt.parse('81c2c92e47edaee6', radix: 16),
    BigInt.parse('92722c851482353b', radix: 16), BigInt.parse('a2bfe8a14cf10364', radix: 16), BigInt.parse('a81a664bbc423001', radix: 16),
    BigInt.parse('c24b8b70d0f89791', radix: 16), BigInt.parse('c76c51a30654be30', radix: 16), BigInt.parse('d192e819d6ef5218', radix: 16),
    BigInt.parse('d69906245565a910', radix: 16), BigInt.parse('f40e35855771202a', radix: 16), BigInt.parse('106aa07032bbd1b8', radix: 16),
    BigInt.parse('19a4c116b8d2d0c8', radix: 16), BigInt.parse('1e376c085141ab53', radix: 16), BigInt.parse('2748774cdf8eeb99', radix: 16),
    BigInt.parse('34b0bcb5e19b48a8', radix: 16), BigInt.parse('391c0cb3c5c95a63', radix: 16), BigInt.parse('4ed8aa4ae3418acb', radix: 16),
    BigInt.parse('5b9cca4f7763e373', radix: 16), BigInt.parse('682e6ff3d6b2b8a3', radix: 16), BigInt.parse('748f82ee5defb2fc', radix: 16),
    BigInt.parse('78a5636f43172f60', radix: 16), BigInt.parse('84c87814a1f0ab72', radix: 16), BigInt.parse('8cc702081a6439ec', radix: 16),
    BigInt.parse('90befffa23631e28', radix: 16), BigInt.parse('a4506cebde82bde9', radix: 16), BigInt.parse('bef9a3f7b2c67915', radix: 16),
    BigInt.parse('c67178f2e372532b', radix: 16), BigInt.parse('ca273eceea26619c', radix: 16), BigInt.parse('d186b8c721c0c207', radix: 16),
    BigInt.parse('eada7dd6cde0eb1e', radix: 16), BigInt.parse('f57d4f7fee6ed178', radix: 16), BigInt.parse('06f067aa72176fba', radix: 16),
    BigInt.parse('0a637dc5a2c898a6', radix: 16), BigInt.parse('113f9804bef90dae', radix: 16), BigInt.parse('1b710b35131c471b', radix: 16),
    BigInt.parse('28db77f523047d84', radix: 16), BigInt.parse('32caab7b40c72493', radix: 16), BigInt.parse('3c9ebe0a15c9bebc', radix: 16),
    BigInt.parse('431d67c49c100d4c', radix: 16), BigInt.parse('4cc5d4becb3e42b6', radix: 16), BigInt.parse('597f299cfc657e2a', radix: 16),
    BigInt.parse('5fcb6fab3ad6faec', radix: 16), BigInt.parse('6c44198c4a475817', radix: 16),
];
// dart format on

Uint8List _padData(Uint8List input) {
  final length = input.length * 8; // length in bits of input
  final data = BytesBuilder();
  data.add(input);
  data.addByte(0x80);
  while ((data.length + 16) % 128 != 0) {
    data.addByte(0x00);
  }
  data.add(bigIntToBytes(BigInt.from(length), minLength: 16));
  assert(data.length % 128 == 0);
  return data.toBytes();
}

State _initializeState() {
  return State(
    BigInt.parse('6a09e667f3bcc908', radix: 16),
    BigInt.parse('bb67ae8584caa73b', radix: 16),
    BigInt.parse('3c6ef372fe94f82b', radix: 16),
    BigInt.parse('a54ff53a5f1d36f1', radix: 16),
    BigInt.parse('510e527fade682d1', radix: 16),
    BigInt.parse('9b05688c2b3e6c1f', radix: 16),
    BigInt.parse('1f83d9abfb41bd6b', radix: 16),
    BigInt.parse('5be0cd19137e2179', radix: 16),
  );
}

BigInt _rotateRight(BigInt x, int n) {
  return (x >> n) | (x << (64 - n)) & _maxInt64;
}

BigInt _sigma0(BigInt x) {
  return _rotateRight(x, 1) ^ _rotateRight(x, 8) ^ (x >> 7);
}

BigInt _sigma1(BigInt x) {
  return _rotateRight(x, 19) ^ _rotateRight(x, 61) ^ (x >> 6);
}

BigInt _sum0(BigInt x) {
  return _rotateRight(x, 28) ^ _rotateRight(x, 34) ^ _rotateRight(x, 39);
}

BigInt _sum1(BigInt x) {
  return _rotateRight(x, 14) ^ _rotateRight(x, 18) ^ _rotateRight(x, 41);
}

BigInt _ch(BigInt x, BigInt y, BigInt z) {
  return (x & y) ^ (~x & z);
}

BigInt _maj(BigInt x, BigInt y, BigInt z) {
  return (x & y) ^ (x & z) ^ (y & z);
}

State _processBlock(Uint8List block, State state) {
  // prepare the message schedule
  final w = List<BigInt>.filled(80, BigInt.zero);
  for (var i = 0; i < 16; i++) {
    w[i] = bytesToBigInt(block.sublist(i * 8, (i + 1) * 8));
  }

  for (var i = 16; i < 80; i++) {
    final term1 = _sigma1(w[i - 2]);
    final term2 = w[i - 7];
    final term3 = _sigma0(w[i - 15]);
    final term4 = w[i - 16];
    w[i] = (term1 + term2 + term3 + term4) & _maxInt64;
  }

  // initialize working variables
  var a = state.h0;
  var b = state.h1;
  var c = state.h2;
  var d = state.h3;
  var e = state.h4;
  var f = state.h5;
  var g = state.h6;
  var h = state.h7;

  // main loop
  for (var i = 0; i < 80; i++) {
    final term1 = (h + _sum1(e) + _ch(e, f, g) + _k[i] + w[i]) & _maxInt64;
    final term2 = (_sum0(a) + _maj(a, b, c)) & _maxInt64;

    h = g;
    g = f;
    f = e;
    e = (d + term1) & _maxInt64;
    d = c;
    c = b;
    b = a;
    a = (term1 + term2) & _maxInt64;
  }

  // intermediate hash value
  state.h0 = (state.h0 + a) & _maxInt64;
  state.h1 = (state.h1 + b) & _maxInt64;
  state.h2 = (state.h2 + c) & _maxInt64;
  state.h3 = (state.h3 + d) & _maxInt64;
  state.h4 = (state.h4 + e) & _maxInt64;
  state.h5 = (state.h5 + f) & _maxInt64;
  state.h6 = (state.h6 + g) & _maxInt64;
  state.h7 = (state.h7 + h) & _maxInt64;

  return state;
}

Uint8List _finalHash(State state) {
  return Uint8List.fromList([
    ...bigIntToBytes(state.h0, minLength: 8),
    ...bigIntToBytes(state.h1, minLength: 8),
    ...bigIntToBytes(state.h2, minLength: 8),
    ...bigIntToBytes(state.h3, minLength: 8),
    ...bigIntToBytes(state.h4, minLength: 8),
    ...bigIntToBytes(state.h5, minLength: 8),
    ...bigIntToBytes(state.h6, minLength: 8),
    ...bigIntToBytes(state.h7, minLength: 8),
  ]);
}

Uint8List sha512(Uint8List data) {
  final paddedData = _padData(data);
  var state = _initializeState();

  for (var i = 0; i < paddedData.length; i += 128) {
    final block = paddedData.sublist(i, i + 128);
    state = _processBlock(block, state);
  }

  return _finalHash(state);
}
