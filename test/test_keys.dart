import 'package:test/test.dart';

import '../lib/keys.dart';
import '../lib/utils.dart';

void main() {
  test('masterKeyFromSeed() generates master key from seed', () {
    var masterKey = masterKeyFromSeed(hexToBytes(
        '7d81060f037fb3fa077a1dbb310d955a5fbffa3f25c8f9b8557efae59f21c85dc4e49bc9a6a0108ef6f87befd16cada2533d6ed042033d15c211f7f1c2ec8e69'));
    expect(
        masterKey.privateKey,
        equals(hexToBytes(
            '9e079f7cfba42e45fa7e14696f59a04b4374ad334ec8834ecdf9526c3c033a27')));
    expect(
        masterKey.publicKey,
        equals(hexToBytes(
            '033c21d5516b1361351f11c29b39045e8b32ec77f71b4e01b34de5d5f32e68eaa1')));
    expect(
        masterKey.chainCode,
        equals(hexToBytes(
            '7ed751a057caf46ce1f1b630f31e74f0076be77a070a231b22a334111836db9e')));
    masterKey = masterKeyFromSeed(hexToBytes(
        '303d8e4e4a7d18f14a8296b5941648ceca152f01d3515e78f77f91e69f20f2b3fa41eb9f29a7e9ac99daff45131aa5779808fdad586ff9edf9e29d6dc65794bc'));
    expect(
        masterKey.privateKey,
        equals(hexToBytes(
            '74a9b945736cd9d064a8263b94a3e4f412aadc6bd59d1b9ab62b170c2739a1a6')));
    expect(
        masterKey.publicKey,
        equals(hexToBytes(
            '0260fea076bb2f4e075c4c497f14fce46b404af5eedcb7e0f03f8f4ae06b0a3316')));
    expect(
        masterKey.chainCode,
        equals(hexToBytes(
            '2706f1f9292cbf818d99185689379175a84c4faf8441b490410b9a1570b358f5')));
  });
}
