import 'dart:convert';
import 'dart:typed_data';

import 'common.dart';

final alphabet = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

Uint8List _hrpExpand(String hrp) {
  final hrpBytes = utf8.encode(hrp);
  final hrpExpanded = Uint8List(hrpBytes.length * 2 + 1);
  for (var i = 0; i < hrpBytes.length; i++) {
    hrpExpanded[i] = hrpBytes[i] >> 5;
  }
  hrpExpanded[hrpBytes.length]; // separator
  for (var i = 0; i < hrpBytes.length; i++) {
    hrpExpanded[hrpBytes.length + i + 1] = hrpBytes[i] & 0x1F; // 11111 = 1F
  }
  print('hrp: $hrp');
  print(
    'hrp bytes: ${hrpBytes.map((b) => b.toRadixString(2).padLeft(8, '0'))}',
  );
  print('hrp expanded: ${_intListAs5Bits(hrpExpanded)}');
  return hrpExpanded;
}

List<String> _splitChunks(String input, {int chunk = 5}) {
  if (chunk <= 0) {
    throw ArgumentError('Chunk size must be greater than zero');
  }
  List<String> list = [];
  if (input.isEmpty) {
    return [];
  }
  if (input.length <= chunk) {
    return [input];
  }
  var i = 0;
  for (i = 0; i < (input.length ~/ chunk); i++) {
    var temp = input.substring(i * chunk, i * chunk + chunk);
    list.add(temp);
  }
  if (input.length % chunk != 0) {
    list.add(input.substring(i * chunk, input.length));
  }
  return list;
}

Uint8List _convert8BitTo5Bit(Uint8List input) {
  final strs8bit = input
      .map((byte) => byte.toRadixString(2).padLeft(8, '0'))
      .join('');
  final strs5bit = _splitChunks(strs8bit);
  return Uint8List.fromList(
    strs5bit.map((s) => int.parse(s, radix: 2)).toList(),
  );
}

Uint8List _convert5BitTo8Bit(Uint8List input) {
  print('input length: ${input.length}');
  // join to big binary string
  var strJoined = input
      .map((byte) => byte.toRadixString(2).padLeft(5, '0'))
      .join('');
  if (strJoined.length % 8 != 0) {
    strJoined = strJoined.substring(
      0,
      strJoined.length - (strJoined.length % 8),
    );
  }
  // Split the string into 8-bit chunks
  final chunks = _splitChunks(strJoined, chunk: 8);
  // Convert each chunk back to an integer
  final bytes = chunks.map((chunk) => int.parse(chunk, radix: 2)).toList();
  // Return as Uint8List
  return Uint8List.fromList(bytes);
}

Uint8List _checksumAs5Bits(int value) {
  if (value < 0 || value > 0x3FFFFFFF) {
    throw ArgumentError('Value must be between 0 and 3FFFFFFF');
  }
  final strs5bit = _splitChunks(value.toRadixString(2).padLeft(30, '0'));
  return Uint8List.fromList(
    strs5bit.map((s) => int.parse(s, radix: 2)).toList(),
  );
}

String _intAs5Bits(int value) {
  if (value < 0 || value > 31) {
    throw ArgumentError('Value must be between 0 and 31');
  }
  return value.toRadixString(2).padLeft(5, '0');
}

String _intListAs5Bits(List<int> values) {
  return values.map(_intAs5Bits).join(' ');
}

Uint8List _bech32Checksum(
  Uint8List hrp,
  int version,
  Uint8List witnessProgram5Bit,
) {
  // checksum input
  final checksumInput = <int>[
    ...hrp,
    version,
    ...witnessProgram5Bit,
    0,
    0,
    0,
    0,
    0,
    0,
  ];
  // initial checksum value
  var checksum = 1;
  // setup generator
  final generator = [
    int.parse('111011011010100101011110110010', radix: 2),
    int.parse('100110010100001000111001101101', radix: 2),
    int.parse('011110101000010001100111111010', radix: 2),
    int.parse('111101010000100011001111011101', radix: 2),
    int.parse('101010000101000110001010110011', radix: 2),
  ];
  // calculate checksum
  for (var i = 0; i < checksumInput.length; i++) {
    print('chk: ${checksum.toRadixString(2).padLeft(30, '0')}');
    // get top 5 bits
    var top = checksum >> (30 - 5);
    print('top: ${top.toRadixString(2).padLeft(5, '0')}');
    // get bottom 25 bits
    var bottom = checksum & 0x1FFFFFF; // 1111111111111111111111111 (25 bits)
    print('bot:      ${bottom.toRadixString(2).padLeft(25, '0')}');
    // pad bottom with 5 bits
    bottom = bottom << 5;
    print('pad:      ${bottom.toRadixString(2).padLeft(30, '0')}');
    // get next value from checksum input
    var nextValue = checksumInput[i];
    print(
      'grp:                               ${nextValue.toRadixString(2).padLeft(5, '0')}',
    );
    // XOR with
    checksum = bottom ^ nextValue;
    print('xor:      ${checksum.toRadixString(2).padLeft(30, '0')}');

    // XOR with generator
    var appliedGen = false;
    if (top & 1 == 1) {
      checksum ^= generator[0];
      appliedGen = true;
    }
    print(
      'gen:      ${generator[0].toRadixString(2).padLeft(30, '0')} ${appliedGen ? 'X' : ''}',
    );
    appliedGen = false;
    if (top & 1 << 1 == 1 << 1) {
      checksum ^= generator[1];
      appliedGen = true;
    }
    print(
      'gen:      ${generator[1].toRadixString(2).padLeft(30, '0')} ${appliedGen ? 'X' : ''}',
    );
    appliedGen = false;
    if (top & 1 << 2 == 1 << 2) {
      checksum ^= generator[2];
      appliedGen = true;
    }
    print(
      'gen:      ${generator[2].toRadixString(2).padLeft(30, '0')} ${appliedGen ? 'X' : ''}',
    );
    appliedGen = false;
    if (top & 1 << 3 == 1 << 3) {
      checksum ^= generator[3];
      appliedGen = true;
    }
    print(
      'gen:      ${generator[3].toRadixString(2).padLeft(30, '0')} ${appliedGen ? 'X' : ''}',
    );
    appliedGen = false;
    if (top & 1 << 4 == 1 << 4) {
      checksum ^= generator[4];
      appliedGen = true;
    }
    print(
      'gen:      ${generator[4].toRadixString(2).padLeft(30, '0')} ${appliedGen ? 'X' : ''}',
    );
    print('chk:      ${checksum.toRadixString(2).padLeft(30, '0')}');
    print('');
  }
  print('checksum: ${_intListAs5Bits(_checksumAs5Bits(checksum))}');
  // XOR with constant
  if (version == 0) {
    // constant for bech32
    checksum ^= 1;
    print('constant: 00000 00000 00000 00000 00000 00001');
  } else {
    // constant for bech32m
    checksum ^= 0x2BC830A3; // 101011110010000011000010100011 = 2BC830A3
  }
  print('checksum: ${_intListAs5Bits(_checksumAs5Bits(checksum))}');
  // split checksum into 5-bit groups
  return _checksumAs5Bits(checksum);
}

String bech32Encode(
  Uint8List scriptPubKey, {
  Network network = Network.mainnet,
}) {
  // human readable part (hrp) based on the network
  final hrp = switch (network) {
    Network.mainnet => 'bc',
    Network.testnet => 'tb',
    Network.regtest => 'bcrt',
  };
  // check scriptPubKey length
  if (scriptPubKey.length < 2) {
    throw ArgumentError('Invalid scriptPubKey length: ${scriptPubKey.length}');
  }
  // get the witness version
  final version = scriptPubKey[0];
  // witness version should be between OP_0 and OP_16
  if (version != 0 && (version < 0x51 && version > 0x60)) {
    throw ArgumentError('Invalid witness version: $version');
  }
  // get the witness size
  final size = scriptPubKey[1];
  // size should be 20 bytes (public key hash - P2WPKH, script hash - P2WSH) or 32 bytes (tweaked public key - P2TR)
  if (size != 20 && size != 32) {
    throw ArgumentError('Invalid witness size: $size');
  }
  // check sciptPubKey length
  if (scriptPubKey.length != size + 2) {
    throw ArgumentError(
      'Invalid scriptPubKey length: ${scriptPubKey.length}, expected: ${size + 2}',
    );
  }
  // expand hrp to 5-bit groups
  final hrpExpanded = _hrpExpand(hrp);
  // bech32 version as 5-bit group
  final bech32Version = (version == 0 ? 0 : version - 0x50);
  print('bech32Version: ${_intAs5Bits(bech32Version)}');
  // convert witness program to 5-bit values
  var witnessProgram = _convert8BitTo5Bit(scriptPubKey.sublist(2));
  print('witnessProgram: ${_intListAs5Bits(witnessProgram)}');
  // calculate checksum
  final checksum = _bech32Checksum(hrpExpanded, bech32Version, witnessProgram);
  print('checksum: $checksum');
  // combine all parts
  final bech32Parts = <int>[bech32Version, ...witnessProgram, ...checksum];
  // convert to bech32 string
  final bech32String = StringBuffer(hrp);
  bech32String.write('1'); // separator
  for (var i = 0; i < bech32Parts.length; i++) {
    bech32String.write(alphabet[bech32Parts[i]]);
  }
  return bech32String.toString();
}

Uint8List bech32Decode(String input) {
  // split input into human readable part (hrp) and data part
  final oneIndex = input.lastIndexOf('1');
  if (oneIndex == -1) {
    throw ArgumentError('Invalid Bech32 input: $input');
  }
  if (oneIndex == 0 || oneIndex == input.length - 1) {
    throw ArgumentError('Invalid Bech32 input: $input');
  }
  final hrp = input.substring(0, oneIndex);
  final data = input.substring(oneIndex + 1);
  // expand hrp to 5-bit groups
  final hrpExpanded = _hrpExpand(hrp);
  // convert data to 5-bit values
  final data5Bit = Uint8List(data.length);
  for (var i = 0; i < data.length; i++) {
    final index = alphabet.indexOf(data[i]);
    if (index == -1) {
      throw ArgumentError('Invalid character in Bech32 input: ${data[i]}');
    }
    data5Bit[i] = index;
  }
  // extract version, witness program, and checksum
  if (data5Bit.length < 7) {
    throw ArgumentError('Bech32 input too short: $input');
  }
  final version = data5Bit[0];
  if (version < 0 || version > 16) {
    throw ArgumentError('Invalid Bech32 version: $version');
  }
  final witnessProgram5Bit = data5Bit.sublist(1, data5Bit.length - 6);
  final checksum = data5Bit.sublist(data5Bit.length - 6);
  // verify checksum
  final calculatedChecksum = _bech32Checksum(
    hrpExpanded,
    version,
    witnessProgram5Bit,
  );
  for (var i = 0; i < 6; i++) {
    if (checksum[i] != calculatedChecksum[i]) {
      throw ArgumentError('Invalid Bech32 checksum: $input');
    }
  }
  // convert version to opcode value
  final opcode = version == 0 ? 0 : version + 0x50;
  // convert witness program back to 8-bit values
  final witnessProgram8Bit = _convert5BitTo8Bit(witnessProgram5Bit);
  // check witness program length
  if (witnessProgram8Bit.length != 20 && witnessProgram8Bit.length != 32) {
    throw ArgumentError(
      'Invalid witness program length: ${witnessProgram8Bit.length}',
    );
  }
  // combine version, witness program length, and witness program
  return Uint8List.fromList([
    opcode,
    witnessProgram8Bit.length,
    ...witnessProgram8Bit,
  ]);
}
