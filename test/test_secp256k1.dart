// ignore_for_file: avoid_relative_lib_imports

import 'package:test/test.dart';

import '../lib/src/secp256k1.dart';

void main() {
  test('generator', () {
    var g = Secp256k1Point.generator;
    expect(g.x.toRadixString(16).length, equals(64));
    expect(g.y.toRadixString(16).length, equals(64));
    expect(
      g.x,
      equals(
        BigInt.parse(
          '0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798',
        ),
      ),
    );
    expect(
      g.y,
      equals(
        BigInt.parse(
          '0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8',
        ),
      ),
    );
  });
  test('point from x odd', () {
    var p = Secp256k1Point.fromX(
      BigInt.parse(
        '95756321671391691422499260635489713855017934320697232784419034040341620768463',
      ),
      YParity.odd,
    );
    expect(
      p.x,
      equals(
        BigInt.parse(
          '95756321671391691422499260635489713855017934320697232784419034040341620768463',
        ),
      ),
    );
    expect(
      p.y,
      equals(
        BigInt.parse(
          '31082383852715566401144521158100549802439663929750477091548749113466916359503',
        ),
      ),
    );
  });
  test('point from x even', () {
    var p = Secp256k1Point.fromX(
      BigInt.parse(
        '89096489680060348378492666920240512821676435969427706206739370292263503437348',
      ),
      YParity.even,
    );
    expect(
      p.x,
      equals(
        BigInt.parse(
          '89096489680060348378492666920240512821676435969427706206739370292263503437348',
        ),
      ),
    );
    expect(
      p.y,
      equals(
        BigInt.parse(
          '114443720505429237542671734873075584269201314367402518484868187858578812995486',
        ),
      ),
    );
  });
  test('double', () {
    var p1 = Secp256k1Point(
      BigInt.parse(
        '743901096182464825610795587469450133376868621566351489756542266957855281511',
      ),
      BigInt.parse(
        '62749339145175942040719300078301132052756548622120605693213839793719809560675',
      ),
    );
    var sum = p1.double();
    expect(
      sum.x,
      equals(
        BigInt.parse(
          '41589302858967743926182352707473920543576251038487516514450312847885993509242',
        ),
      ),
    );
    expect(
      sum.y,
      equals(
        BigInt.parse(
          '33322889027850177977704557580322205879229340782703663571974746182168266804703',
        ),
      ),
    );
  });
  test('add', () {
    var p1 = Secp256k1Point(
      BigInt.parse(
        '65340934303069757366510384714354898097253406084811389610093719698526595568922',
      ),
      BigInt.parse(
        '80421494332251042537797949540455727804955207480095219603087605553883066061385',
      ),
    );
    var p2 = Secp256k1Point(
      BigInt.parse(
        '109880807793501134912169489284694122723455610213334821826541931378088273713515',
      ),
      BigInt.parse(
        '16038999092160430908412829870425301935004268133731728538073276641880014580907',
      ),
    );
    var sum = p1.add(p2);
    expect(
      sum.x,
      equals(
        BigInt.parse(
          '1021774475266655020926522622474089428715670307595346950471928962573030390755',
        ),
      ),
    );
    expect(
      sum.y,
      equals(
        BigInt.parse(
          '68888535382694591920854628813082336007971836379585274431228891516435301097050',
        ),
      ),
    );
  });
  test('multiply', () {
    var p1 = Secp256k1Point(
      BigInt.parse(
        '34242188945067101413716617307168529957638082476437459116624460943920543897226',
      ),
      BigInt.parse(
        '48210024665282525638618286475972791054082276806041293672227495821478888145863',
      ),
    );
    var k = BigInt.parse('1000');
    var product = p1.multiply(k);
    expect(
      product.x,
      equals(
        BigInt.parse(
          '83723336421285921868385390675713021136715807623009105443807242744383923387701',
        ),
      ),
    );
    expect(
      product.y,
      equals(
        BigInt.parse(
          '17218992124255626687198830362813985704513598052631189285955841516512707689094',
        ),
      ),
    );
    k = BigInt.parse('1001');
    product = p1.multiply(k);
    expect(
      product.x,
      equals(
        BigInt.parse(
          '12248853647586580765514019397435331849983171555411141660461133463055461182960',
        ),
      ),
    );
    expect(
      product.y,
      equals(
        BigInt.parse(
          '31739904658023192471655687097165377423183194154022656882498166976113558944136',
        ),
      ),
    );
    // test when first bit of 256 is 1
    k = BigInt.parse(
      '8000000000000000000000000000000000000000000000000000000000000000',
      radix: 16,
    );
    product = p1.multiply(k);
    expect(
      product.x,
      equals(
        BigInt.parse(
          '75327484772108024847324083535689541793369126435474927081400325469160917981057',
        ),
      ),
    );
    expect(
      product.y,
      equals(
        BigInt.parse(
          '88325491223574713731534894112075491544223292429032811547152986225410453799956',
        ),
      ),
    );
  });
}
