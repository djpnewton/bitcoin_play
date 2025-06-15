// ignore_for_file: avoid_relative_lib_imports

import 'package:test/test.dart';

import '../lib/src/utils.dart';
import '../lib/src/common.dart';
import '../lib/src/address.dart';

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
    final publicKey = hexToBytes(
      '030305aff85dd48d32aa8fea019e09bed36db9db18b46f8339d0ad1cd7a11210c9',
    );
    final addressMainnet = p2shP2wpkhAddress(
      publicKey,
      network: Network.mainnet,
    );
    final addressTestnet = p2shP2wpkhAddress(
      publicKey,
      network: Network.testnet,
    );
    expect(addressMainnet, equals('3EGHyaUqjngxeaMrDC8KaNE3R2rfmADUqM'));
    expect(addressTestnet, equals('2N5pW3KQsMFCJrMzPtKkCCKDJdP4qdAy7tD'));
    // invalid length
    var publicKeyInvalid = hexToBytes(
      '030305aff85dd48d32aa8fea019e09bed36db9db18b46f8339d0ad1cd7a11210c9ff',
    );
    expect(
      () => p2shP2wpkhAddress(publicKeyInvalid, network: Network.mainnet),
      throwsArgumentError,
    );
    // invalid prefix
    publicKeyInvalid = hexToBytes(
      '050305aff85dd48d32aa8fea019e09bed36db9db18b46f8339d0ad1cd7a11210c9',
    );
    expect(
      () => p2shP2wpkhAddress(publicKeyInvalid, network: Network.mainnet),
      throwsArgumentError,
    );
  });
  test('p2wpkhAddress() creates a P2WPKH address', () {
    var publicKey = hexToBytes(
      '02d0b6a6e2acf8f3c2ff2bd17ebb01798924db2c42f0f6724fa09169a72cc48dae',
    );
    var addressMainnet = p2wpkhAddress(publicKey, network: Network.mainnet);
    var addressTestnet = p2wpkhAddress(publicKey, network: Network.testnet);
    expect(
      addressMainnet,
      equals('bc1qmdextqm66f2prkp4vkjexsc6trp56956w5rm0e'),
    );
    expect(
      addressTestnet,
      equals('tb1qmdextqm66f2prkp4vkjexsc6trp56956yjcg52'),
    );
    // invalid length
    var publicKeyInvalid = hexToBytes(
      '02d0b6a6e2acf8f3c2ff2bd17ebb01798924db2c42f0f6724fa09169a72cc48daeff',
    );
    expect(
      () => p2wpkhAddress(publicKeyInvalid, network: Network.mainnet),
      throwsArgumentError,
    );
    // invalid prefix
    publicKeyInvalid = hexToBytes(
      '06d0b6a6e2acf8f3c2ff2bd17ebb01798924db2c42f0f6724fa09169a72cc48dae',
    );
    expect(
      () => p2wpkhAddress(publicKeyInvalid, network: Network.mainnet),
      throwsArgumentError,
    );
  });
}
