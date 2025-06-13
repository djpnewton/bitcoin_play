// ignore_for_file: avoid_relative_lib_imports

import 'package:test/test.dart';

import '../lib/utils.dart';
import '../lib/common.dart';
import '../lib/address.dart';

void main() {
  test('p2pkhAddress() creates a P2PKH address', () {
    final publicKey = hexToBytes(
      '0207a22257fad2aa0f48cc46c60681117af064482624a329c217e728bcea419265',
    );
    final addressMainnet = p2pkhAddress(publicKey, network: Network.mainnet);
    final addressTestnet = p2pkhAddress(publicKey, network: Network.testnet);
    expect(addressMainnet, equals('17CAWEuEXomN3GqbMtZ7YvRyziaveBNBxo'));
    expect(addressTestnet, equals('mmi7oHzDLqCcpPKD5TXVNqeJriBdZqZNgC'));
    // invalid length
    var publicKeyInvalid = hexToBytes('0207a22257fad2aa0f48cc46c606');
    expect(
      () => p2pkhAddress(publicKeyInvalid, network: Network.mainnet),
      throwsArgumentError,
    );
    // invalid prefix
    publicKeyInvalid = hexToBytes(
      '0107a22257fad2aa0f48cc46c60681117af064482624a329c217e728bcea419265',
    );
    expect(
      () => p2pkhAddress(publicKeyInvalid, network: Network.mainnet),
      throwsArgumentError,
    );
  });
  test('p2shP2wpkhAddress() creates a P2SH-P2WPKH address', () {
    //TODO
  });
  test('p2wpkhAddress() creates a P2WPKH address', () {
    //TODO
  });
}
