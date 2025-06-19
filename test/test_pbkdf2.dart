// ignore_for_file: avoid_relative_lib_imports

import 'dart:convert';

import 'package:test/test.dart';

import '../lib/src/pbkdf2.dart';
import '../lib/src/utils.dart';

void main() {
  test('pbkdf2', () {
    expect(
      () => pbkdf2(
        MacAlgorithm.hmacSha256,
        utf8.encode('pass'),
        utf8.encode('salt'),
        iterations: 0,
        bits: 256,
      ),
      equals(throwsArgumentError),
    );
    expect(
      () => pbkdf2(
        MacAlgorithm.hmacSha256,
        utf8.encode('pass'),
        utf8.encode('salt'),
        iterations: 1000,
        bits: 0,
      ),
      equals(throwsArgumentError),
    );
    expect(
      pbkdf2(
        MacAlgorithm.hmacSha256,
        utf8.encode('pass'),
        utf8.encode('salt'),
        iterations: 1000,
        bits: 256,
      ),
      equals(
        hexToBytes(
          'ce7834ce3ad3ce55207a94de959d37afbd9f8eea479d46cbe7959a53d1ab5ecb',
        ),
      ),
    );
    expect(
      pbkdf2(
        MacAlgorithm.hmacSha512,
        utf8.encode('pass'),
        utf8.encode('salt'),
        iterations: 1000,
        bits: 512,
      ),
      equals(
        hexToBytes(
          'be9f9b741fdb999754113a39f2402255185ef699103480c977f3f2b53e116a4ab93ea4578eb0363d6de6a7cadb3a3868fb3c84cbadbd7781600cc485ad4a478b',
        ),
      ),
    );
    expect(
      pbkdf2(
        MacAlgorithm.hmacSha256,
        utf8.encode('the quick brown fox jumped over the lazy dog'),
        utf8.encode('mary had a little lamb'),
        iterations: 1000,
        bits: 256,
      ),
      equals(
        hexToBytes(
          'c0d2be076d55221c858b932a9baf0af6b0981a54c0b63255ac6c0437b96f91a7',
        ),
      ),
    );
    expect(
      pbkdf2(
        MacAlgorithm.hmacSha512,
        utf8.encode('the quick brown fox jumped over the lazy dog'),
        utf8.encode('mary had a little lamb'),
        iterations: 1000,
        bits: 512,
      ),
      equals(
        hexToBytes(
          '2711acdac47b4cb1da59a9c84fd710d9ea48993d256fa96e6e72ca6b0a2d4de7beddbf76707213820dbc8e33ae8111e60483547719a471e98a55f90bffb3498a',
        ),
      ),
    );
    expect(
      pbkdf2(
        MacAlgorithm.hmacSha256,
        utf8.encode(
          'd5e3f89df30232f657246bb50d97f92e2053fcd4e37b326fe94f2c2ff67afffc320e529079ac904f2c0ff70f21129d91608b5d93e2469b28832c4e59266b2d3436363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636',
        ),
        utf8.encode(
          'bf8992f79968589c3d4e01df67fd93444a3996be89115805832546459c109596586438fa13c6fa2546659d654b78f7fb0ae137f9882cf142e94624334c01475e5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c',
        ),
        iterations: 1000,
        bits: 256,
      ),
      equals(
        hexToBytes(
          '6df9b4e467371ed6169a73328fab6cc72e0ff448e7cc74b915c9e6cc7e98ce52',
        ),
      ),
    );
    expect(
      pbkdf2(
        MacAlgorithm.hmacSha512,
        utf8.encode(
          'd5e3f89df30232f657246bb50d97f92e2053fcd4e37b326fe94f2c2ff67afffc320e529079ac904f2c0ff70f21129d91608b5d93e2469b28832c4e59266b2d3436363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636',
        ),
        utf8.encode(
          'bf8992f79968589c3d4e01df67fd93444a3996be89115805832546459c109596586438fa13c6fa2546659d654b78f7fb0ae137f9882cf142e94624334c01475e5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c',
        ),
        iterations: 1000,
        bits: 512,
      ),
      equals(
        hexToBytes(
          '6f9556bddfef9aaa0574750db88cb2706c29e245ee8f23778880ef918ee9a7b92503034530fb5179c85b0352b5ce2f9bf1f964395dc7b486fb9cf623c6e9033d',
        ),
      ),
    );
  });
  test(
    'pbkdf2 https://github.com/brycx/Test-Vector-Generation/blob/master/PBKDF2/pbkdf2-hmac-sha2-test-vectors.md',
    () {
      // Test Case 1
      expect(
        pbkdf2(
          MacAlgorithm.hmacSha256,
          utf8.encode('password'),
          utf8.encode('salt'),
          iterations: 1,
          bits: 160,
        ),
        equals(hexToBytes('120fb6cffcf8b32c43e7225256c4f837a86548c9')),
      );
      expect(
        pbkdf2(
          MacAlgorithm.hmacSha512,
          utf8.encode('password'),
          utf8.encode('salt'),
          iterations: 1,
          bits: 160,
        ),
        equals(hexToBytes('867f70cf1ade02cff3752599a3a53dc4af34c7a6')),
      );
      // Test Case 2
      expect(
        pbkdf2(
          MacAlgorithm.hmacSha256,
          utf8.encode('password'),
          utf8.encode('salt'),
          iterations: 2,
          bits: 160,
        ),
        equals(hexToBytes('ae4d0c95af6b46d32d0adff928f06dd02a303f8e')),
      );
      expect(
        pbkdf2(
          MacAlgorithm.hmacSha512,
          utf8.encode('password'),
          utf8.encode('salt'),
          iterations: 2,
          bits: 160,
        ),
        equals(hexToBytes('e1d9c16aa681708a45f5c7c4e215ceb66e011a2e')),
      );
      // Test Case 3
      expect(
        pbkdf2(
          MacAlgorithm.hmacSha256,
          utf8.encode('password'),
          utf8.encode('salt'),
          iterations: 4096,
          bits: 160,
        ),
        equals(hexToBytes('c5e478d59288c841aa530db6845c4c8d962893a0')),
      );
      expect(
        pbkdf2(
          MacAlgorithm.hmacSha512,
          utf8.encode('password'),
          utf8.encode('salt'),
          iterations: 4096,
          bits: 160,
        ),
        equals(hexToBytes('d197b1b33db0143e018b12f3d1d1479e6cdebdcc')),
      );
      // Test Case 4
      /*
      expect(
        pbkdf2(
          MacAlgorithm.hmacSha256,
          utf8.encode('password'),
          utf8.encode('salt'),
          iterations: 16777216,
          bits: 160,
        ),
        equals(hexToBytes('cf81c66fe8cfc04d1f31ecb65dab4089f7f179e8')),
      );
      expect(
        pbkdf2(
          MacAlgorithm.hmacSha512,
          utf8.encode('password'),
          utf8.encode('salt'),
          iterations: 16777216,
          bits: 160,
        ),
        equals(hexToBytes('6180a3ceabab45cc3964112c811e0131bca93a35')),
      );
      */
      // Test Case 5
      expect(
        pbkdf2(
          MacAlgorithm.hmacSha256,
          utf8.encode('passwordPASSWORDpassword'),
          utf8.encode('saltSALTsaltSALTsaltSALTsaltSALTsalt'),
          iterations: 4096,
          bits: 25 * 8,
        ),
        equals(
          hexToBytes('348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c'),
        ),
      );
      expect(
        pbkdf2(
          MacAlgorithm.hmacSha512,
          utf8.encode('passwordPASSWORDpassword'),
          utf8.encode('saltSALTsaltSALTsaltSALTsaltSALTsalt'),
          iterations: 4096,
          bits: 25 * 8,
        ),
        equals(
          hexToBytes('8c0511f4c6e597c6ac6315d8f0362e225f3c501495ba23b868'),
        ),
      );
      // Test Case 6
      expect(
        pbkdf2(
          MacAlgorithm.hmacSha256,
          utf8.encode('pass\x00word'),
          utf8.encode('sa\x00lt'),
          iterations: 4096,
          bits: 16 * 8,
        ),
        equals(hexToBytes('89b69d0516f829893c696226650a8687')),
      );
      expect(
        pbkdf2(
          MacAlgorithm.hmacSha512,
          utf8.encode('pass\x00word'),
          utf8.encode('sa\x00lt'),
          iterations: 4096,
          bits: 16 * 8,
        ),
        equals(hexToBytes('9d9e9c4cd21fe4be24d5b8244c759665')),
      );
      // Test Case 7
      expect(
        pbkdf2(
          MacAlgorithm.hmacSha256,
          utf8.encode('passwd'),
          utf8.encode('salt'),
          iterations: 1,
          bits: 128 * 8,
        ),
        equals(
          hexToBytes(
            '55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783c294e850150390e1160c34d62e9665d659ae49d314510fc98274cc79681968104b8f89237e69b2d549111868658be62f59bd715cac44a1147ed5317c9bae6b2a',
          ),
        ),
      );
      expect(
        pbkdf2(
          MacAlgorithm.hmacSha512,
          utf8.encode('passwd'),
          utf8.encode('salt'),
          iterations: 1,
          bits: 128 * 8,
        ),
        equals(
          hexToBytes(
            'c74319d99499fc3e9013acff597c23c5baf0a0bec5634c46b8352b793e324723d55caa76b2b25c43402dcfdc06cdcf66f95b7d0429420b39520006749c51a04ef3eb99e576617395a178ba33214793e48045132928a9e9bf2661769fdc668f31798597aaf6da70dd996a81019726084d70f152baed8aafe2227c07636c6ddece',
          ),
        ),
      );
      // Test Case 8
      /*
      expect(
        pbkdf2(
          MacAlgorithm.hmacSha256,
          utf8.encode('Password'),
          utf8.encode('NaCl'),
          iterations: 80000,
          bits: 128 * 8,
        ),
        equals(
          hexToBytes(
            '4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d62aae85a11cdde829d89cb6ffd1ab0e63a981f8747d2f2f9fe5874165c83c168d2eed1d2d5ca4052dec2be5715623da019b8c0ec87dc36aa751c38f9893d15c3',
          ),
        ),
      );
      expect(
        pbkdf2(
          MacAlgorithm.hmacSha512,
          utf8.encode('Password'),
          utf8.encode('NaCl'),
          iterations: 80000,
          bits: 128 * 8,
        ),
        equals(
          hexToBytes(
            'e6337d6fbeb645c794d4a9b5b75b7b30dac9ac50376a91df1f4460f6060d5addb2c1fd1f84409abacc67de7eb4056e6bb06c2d82c3ef4ccd1bded0f675ed97c65c33d39f81248454327aa6d03fd049fc5cbb2b5e6dac08e8ace996cdc960b1bd4530b7e754773d75f67a733fdb99baf6470e42ffcb753c15c352d4800fb6f9d6',
          ),
        ),
      );
      */
      // Test Case 9
      expect(
        pbkdf2(
          MacAlgorithm.hmacSha256,
          utf8.encode('Password'),
          utf8.encode('sa\x00lt'),
          iterations: 4096,
          bits: 256 * 8,
        ),
        equals(
          hexToBytes(
            '436c82c6af9010bb0fdb274791934ac7dee21745dd11fb57bb90112ab187c495ad82df776ad7cefb606f34fedca59baa5922a57f3e91bc0e11960da7ec87ed0471b456a0808b60dff757b7d313d4068bf8d337a99caede24f3248f87d1bf16892b70b076a07dd163a8a09db788ae34300ff2f2d0a92c9e678186183622a636f4cbce15680dfea46f6d224e51c299d4946aa2471133a649288eef3e4227b609cf203dba65e9fa69e63d35b6ff435ff51664cbd6773d72ebc341d239f0084b004388d6afa504eee6719a7ae1bb9daf6b7628d851fab335f1d13948e8ee6f7ab033a32df447f8d0950809a70066605d6960847ed436fa52cdfbcf261b44d2a87061',
          ),
        ),
      );
      expect(
        pbkdf2(
          MacAlgorithm.hmacSha512,
          utf8.encode('Password'),
          utf8.encode('sa\x00lt'),
          iterations: 4096,
          bits: 256 * 8,
        ),
        equals(
          hexToBytes(
            '10176fb32cb98cd7bb31e2bb5c8f6e425c103333a2e496058e3fd2bd88f657485c89ef92daa0668316bc23ebd1ef88f6dd14157b2320b5d54b5f26377c5dc279b1dcdec044bd6f91b166917c80e1e99ef861b1d2c7bce1b961178125fb86867f6db489a2eae0022e7bc9cf421f044319fac765d70cb89b45c214590e2ffb2c2b565ab3b9d07571fde0027b1dc57f8fd25afa842c1056dd459af4074d7510a0c020b914a5e202445d4d3f151070589dd6a2554fc506018c4f001df6239643dc86771286ae4910769d8385531bba57544d63c3640b90c98f1445ebdd129475e02086b600f0beb5b05cc6ca9b3633b452b7dad634e9336f56ec4c3ac0b4fe54ced8',
          ),
        ),
      );
    },
  );
}
