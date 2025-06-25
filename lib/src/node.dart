import 'dart:io';
import 'dart:typed_data';

import 'package:logging/logging.dart';

import 'utils.dart';
import 'p2p_messages.dart';
import 'common.dart';

final _log = Logger('Node');

Uint8List _ipv4ToIpv6(String ipv4) {
  final parts = ipv4.split('.');
  if (parts.length != 4) {
    throw FormatException('Invalid IPv4 address');
  }
  return Uint8List.fromList(
    '00000000000000000000ffff'.toBytes() +
        [
          int.parse(parts[0]),
          int.parse(parts[1]),
          int.parse(parts[2]),
          int.parse(parts[3]),
        ],
  );
}

class Peer {
  String ip;
  int port;

  Peer({required this.ip, required this.port});
}

class Node {
  Map<Peer, Socket> connections = {};
  String userAgent = '/dartcoin:0.1/';
  Network network;

  Node({required this.network});

  static int defaultPort(Network network) {
    return Network.mainnet == Network.mainnet ? 8333 : 18333;
  }

  static Future<String> ipFromDnsSeed() async {
    final seeds = [
      'seed.bitcoin.sipa.be',
      'dnsseed.bluematt.me',
      'dnsseed.bitcoin.dashjr.org',
      'seed.bitcoin.sprovoost.nl',
      'seed.bitcoinstats.com',
      'seed.bitnodes.io',
    ];
    final randomSeed =
        seeds[DateTime.now().millisecondsSinceEpoch % seeds.length];
    _log.info('Using DNS seed: $randomSeed');
    try {
      final addresses = await InternetAddress.lookup(
        randomSeed,
        type: InternetAddressType.IPv4,
      );
      if (addresses.isNotEmpty && addresses[0].rawAddress.isNotEmpty) {
        _log.info('Found ${addresses.length} addresses for seed $randomSeed');
        final randomAddress =
            addresses[DateTime.now().millisecondsSinceEpoch % addresses.length];
        _log.info('Random address: ${randomAddress.address}');
        return randomAddress.address;
      }
    } catch (e) {
      _log.severe('Error occurred while looking up DNS seed: $e');
      rethrow;
    }
    throw Exception('No valid IP address found for DNS seed: $randomSeed');
  }

  void connectPeer(Peer peer) async {
    final localPort = defaultPort(network);
    final localIp = '127.0.0.1';

    // connect to the peer
    _log.info('Connecting to peer: ${peer.ip}:${peer.port}');
    try {
      final socket = await Socket.connect(peer.ip, peer.port);
      connections[peer] = socket;
      _log.info('Connected to peer: ${peer.ip}:${peer.port}');
      final versionBytes = MessageVersion(
        timestamp: DateTime.now().millisecondsSinceEpoch ~/ 1000,
        remoteAddress: _ipv4ToIpv6(peer.ip),
        remotePort: peer.port,
        localAddress: _ipv4ToIpv6(localIp),
        localPort: localPort,
        nonce: 0,
        userAgent: userAgent,
        lastBlock: 0,
        relay: false,
      ).toBytes(network);
      _log.info('>>>>>: ${peer.ip}:${peer.port}, Version');
      socket.add(versionBytes);
      socket.listen(
        (data) {
          // Handle incoming data
          //_log.info('<<<<<: ${peer.ip}:${peer.port}, Data: ${data.toHex()}');
          // check what message type is received
          try {
            final message = Message.fromBytes(data, network);
            if (message is MessageVersion) {
              _log.info(
                '<<<<<: ${peer.ip}:${peer.port}, Version: ${message.version}, User Agent: ${message.userAgent}, Last Block: ${message.lastBlock}',
              );
              _log.info('>>>>>: ${peer.ip}:${peer.port}, Verack');
              socket.add(MessageVerack().toBytes(network));
            } else if (message is MessageVerack) {
              _log.info('<<<<<: ${peer.ip}:${peer.port}, Verack');
            } else if (message is MessagePing) {
              _log.info(
                '<<<<<: ${peer.ip}:${peer.port}, Ping: ${message.nonce}',
              );
              _log.info('>>>>>: ${peer.ip}:${peer.port}, Pong');
              socket.add(MessagePong(nonce: message.nonce).toBytes(network));
            } else if (message is MessagePong) {
              _log.info(
                '<<<<<: ${peer.ip}:${peer.port}, Pong: ${message.nonce}',
              );
            } else if (message is MessageInv) {
              _log.info(
                '<<<<<: ${peer.ip}:${peer.port}, Inv: ${message.inventory.length}',
              );
              for (final inv in message.inventory) {
                _log.info(
                  '       Inventory: Type: ${inv.type.name}, Hash: ${inv.hash.toHex()}',
                );
              }
            } else if (message is MessageUnknown) {
              _log.info(
                '<<<<<: ${peer.ip}:${peer.port}, Unknown: ${message.command}',
              );
            }
          } catch (e) {
            _log.severe(
              'Error parsing message from peer: ${peer.ip}:${peer.port}, Error: $e',
            );
          }
        },
        onDone: () {
          // Handle socket closure
          connections.remove(peer);
          _log.info('Disconnected from peer: ${peer.ip}:${peer.port}');
        },
        onError: (error) {
          _log.severe(
            'Error occurred while communicating with peer: ${peer.ip}:${peer.port}, Error: $error',
          );
        },
      );
    } catch (error) {
      _log.severe(
        'Failed to connect to peer: ${peer.ip}:${peer.port}, Error: $error',
      );
    }
  }
}
