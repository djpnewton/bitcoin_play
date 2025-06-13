enum YParity { odd, even }

class Secp256k1Point {
  // secp256k1 curve y² = x³ + ax + b
  final BigInt x;
  final BigInt y;

  static final BigInt a = BigInt.zero; // a = 0 for secp256k1
  static final BigInt b = BigInt.from(7); // b = 7 for secp256k1
  static final BigInt p = BigInt.parse(
    '0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F',
  ); // prime modulus for secp256k1
  static final BigInt n = BigInt.parse(
    '0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141',
  ); // order of the curve
  static final Secp256k1Point generator = Secp256k1Point(
    BigInt.parse(
      '0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798',
    ),
    BigInt.parse(
      '0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8',
    ),
  );

  Secp256k1Point(this.x, this.y);

  factory Secp256k1Point.fromX(BigInt x, YParity yParity) {
    // Calculate y² = x³ + ax + b
    // well a is 0 so we can simplify this to y² = x³ + b
    final ySquared = (x.modPow(BigInt.from(3), p) + b) % p;

    // in Secp256k1 is the square root of y is y^((p + 1) / 4)
    final pPlusOne = p + BigInt.from(1);
    var y = ySquared.modPow(pPlusOne ~/ BigInt.from(4), p);

    // check y
    if (y.modPow(BigInt.from(2), p) != ySquared) {
      throw ArgumentError('Invalid X ($x): no point on the curve for this x');
    }

    // select the correct value for y
    if (yParity == YParity.even && y % BigInt.two != BigInt.zero) {
      y = (p - y) % p;
    }
    if (yParity == YParity.odd && y % BigInt.two == BigInt.zero) {
      y = (p - y) % p;
    }
    return Secp256k1Point(x, y);
  }

  Secp256k1Point double() {
    // slope = (3x² + a) / 2y
    final slope =
        ((BigInt.from(3) * x.pow(2) + a) * _inverse((BigInt.two * y), p));

    // xNew = slope² - 2x
    final xNew = (slope.pow(2) - (BigInt.two * x)) % p;

    // yNew = slope * (x - xNew) - y
    final yNew = (slope * (x - xNew) - y) % p;

    return Secp256k1Point(xNew, yNew);
  }

  Secp256k1Point add(Secp256k1Point other) {
    // if this point is the same as the other point, return double this point
    if (this == other) return double();

    // slope = (y1 - y2) / (x1 - x2)
    final slope = ((y - other.y) * _inverse((x - other.x), p)) % p;

    // xNew = slope² - x1 - x2
    final xNew = (slope.pow(2) - x - other.x) % p;

    // yNew = slope * (x1 - xNew) - y1
    final yNew = (slope * (x - xNew) - y) % p;

    return Secp256k1Point(xNew, yNew);
  }

  Secp256k1Point multiply(BigInt k) {
    // double-and-add algorithm
    Secp256k1Point current = this;
    final binary = k.toRadixString(2);

    binary.runes.skip(1).forEach((c) {
      var char = String.fromCharCode(c);
      current = current.double();
      if (char == '1') {
        current = current.add(this);
      }
    });

    return current;
  }
}

BigInt _inverse(BigInt a, BigInt modulus) {
  // extended Euclidean algorithm to find the modular inverse
  BigInt modulusOriginal = modulus;

  // ensure a is positive
  if (a < BigInt.zero) {
    a = a % modulus;
  }

  // set initial loop values
  BigInt yPrev = BigInt.zero, y = BigInt.one;

  while (a > BigInt.one) {
    BigInt q = modulus ~/ a;

    BigInt yBefore = y;
    y = yPrev - q * y;
    yPrev = yBefore;

    BigInt aBefore = a;
    a = modulus % a;
    modulus = aBefore;
  }

  return y % modulusOriginal;
}
