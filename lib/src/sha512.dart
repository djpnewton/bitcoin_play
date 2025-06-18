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
const _k = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc, 0x3956c25bf348b538, 0x59f111f1b605d019,
    0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242,
    0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
    0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 0x2de92c6f592b0275,
    0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f,
    0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
    0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc,
    0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6,
    0x92722c851482353b, 0xa2bfe8a14cf10364, 0xa81a664bbc423001,
    0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
    0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc,
    0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915,
    0xc67178f2e372532b, 0xca273eceea26619c, 0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba,
    0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
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
    BigInt.from(0x6a09e667f3bcc908),
    BigInt.from(0xbb67ae8584caa73b),
    BigInt.from(0x3c6ef372fe94f82b),
    BigInt.from(0xa54ff53a5f1d36f1),
    BigInt.from(0x510e527fade682d1),
    BigInt.from(0x9b05688c2b3e6c1f),
    BigInt.from(0x1f83d9abfb41bd6b),
    BigInt.from(0x5be0cd19137e2179),
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
    final term1 =
        (h + _sum1(e) + _ch(e, f, g) + BigInt.from(_k[i]) + w[i]) & _maxInt64;
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
    ...bigIntToBytes(state.h0),
    ...bigIntToBytes(state.h1),
    ...bigIntToBytes(state.h2),
    ...bigIntToBytes(state.h3),
    ...bigIntToBytes(state.h4),
    ...bigIntToBytes(state.h5),
    ...bigIntToBytes(state.h6),
    ...bigIntToBytes(state.h7),
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
