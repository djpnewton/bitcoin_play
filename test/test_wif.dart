// ignore_for_file: avoid_relative_lib_imports

import 'package:test/test.dart';

import '../lib/utils.dart';
import '../lib/common.dart';
import '../lib/wif.dart';

void main() {
  test('toWifString() creates WIF string', () {
    var wif =
        Wif(
          Network.mainnet,
          hexToBytes(
            'b3ff86d8d19fd1d9b6b6691b75f8b291af3a2285700cf608495bbc9e0639b719',
          ),
          true,
        ).toWifString();
    expect(wif, equals('L3FbyKikEg3DBY88Dp4iHVsAwfJWRjbSVuY1ECQTuq1TvkuntpFW'));
    wif =
        Wif(
          Network.testnet,
          hexToBytes(
            '8a36eaeed160837630d1b24f8bacd139aaf8318c588ca3d085c12b090879a8b3',
          ),
          true,
        ).toWifString();
    expect(wif, equals('cSDNZiU8cg8VMsidiqoFSKMBfydJMUMr1PDecvde8asrQ5NT44cn'));
    wif =
        Wif(
          Network.testnet,
          hexToBytes(
            '9708d206fbc09ddde7048950eaf857893ed9a4ce525551ce0bf76cb79be35490',
          ),
          false,
        ).toWifString();
    expect(wif, equals('92jS8pYoXzvbdnCdVpHQHiUpdPLD1crkh24CYy632onyAdxNLJg'));
  });
  test('fromWifString() parses WIF string', () {
    var wif = Wif.fromWifString(
      'L3FbyKikEg3DBY88Dp4iHVsAwfJWRjbSVuY1ECQTuq1TvkuntpFW',
    );
    expect(wif.network, equals(Network.mainnet));
    expect(
      wif.privateKey,
      equals(
        hexToBytes(
          'b3ff86d8d19fd1d9b6b6691b75f8b291af3a2285700cf608495bbc9e0639b719',
        ),
      ),
    );
    expect(wif.compressed, isTrue);
    wif = Wif.fromWifString(
      'cSDNZiU8cg8VMsidiqoFSKMBfydJMUMr1PDecvde8asrQ5NT44cn',
    );
    expect(wif.network, equals(Network.testnet));
    expect(
      wif.privateKey,
      equals(
        hexToBytes(
          '8a36eaeed160837630d1b24f8bacd139aaf8318c588ca3d085c12b090879a8b3',
        ),
      ),
    );
    expect(wif.compressed, isTrue);
    wif = Wif.fromWifString(
      '92jS8pYoXzvbdnCdVpHQHiUpdPLD1crkh24CYy632onyAdxNLJg',
    );
    expect(wif.network, equals(Network.testnet));
    expect(
      wif.privateKey,
      equals(
        hexToBytes(
          '9708d206fbc09ddde7048950eaf857893ed9a4ce525551ce0bf76cb79be35490',
        ),
      ),
    );
    expect(wif.compressed, isFalse);
    // Invalid WIF should throw FormatException
    expect(() => Wif.fromWifString('invalid'), throwsFormatException);
    expect(() => Wif.fromWifString(''), throwsFormatException);
    // invalid checksum
    expect(
      () => Wif.fromWifString(
        '92jS8pYoXzvbdnCdVpHQHiUpdPLD1crkh24CYy632onxxxxxxxx',
      ),
      throwsFormatException,
    );
    // invalid length
    expect(
      () => Wif.fromWifString(
        '2pX1FuuyJu6M5i466d65NTcksPH8hvSKWTXBKa6fybcnrRfEoy',
      ),
      throwsFormatException,
    );
    // invalid prefix
    expect(
      () => Wif.fromWifString(
        '18WGDGasA3KZRADNQdCSU5YuYAZ95WuSuzDm2wNX4qURGWby6UDve6vw',
      ),
      throwsFormatException,
    );
  });
}
