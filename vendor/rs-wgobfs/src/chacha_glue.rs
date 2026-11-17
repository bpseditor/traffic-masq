
use rand_core::block::BlockRng;
use rand_core::RngCore;
use crate::chacha::{ChaCha6Core, ChaCha6Rng};
use crate::guts::ChaCha;

pub type ChaChaCore = ChaCha6Core;
pub type ChaChaRng = ChaCha6Rng;

// const XT_WGOBFS_MAX_KEY_SIZE: usize = 32;
// const XT_CHACHA_KEY_SIZE: usize = 32;
// const CHACHA_INPUT_SIZE: usize = 16;
// const CHACHA20_KEY_SIZE: usize = 32;

// ChaCha layout in 32-bit words:
//
// constant  constant  constant  constant
// seed      seed      seed      seed
// seed      seed      seed      seed
// counter1   counter2   stream_id1 stream_id2
//
// put the 32-byte key into seed; 16-byte input into counter and stream_id

pub(crate) fn chacha_hash(input: &[u8; 16], key: &[u8; 32],
                          out: &mut [u8], out_words: usize) {

    let rngcore = ChaChaCore {
        state: ChaCha::new_nonce16(key, input)
    };

    let mut rng = ChaChaRng {
        rng: BlockRng::new(rngcore),
    };


    for i in 0..out_words {
        let bytes = rng.next_u32().to_le_bytes();
        let start = i * 4;
        out[start..start+4].copy_from_slice(&bytes);
    }
}


#[test]
fn test_chacha6() {
    let key: [u8; 32] = [
        1, 2, 3, 4, 5, 6, 7, 8,
        1, 2, 3, 4, 5, 6, 7, 8,
        1, 2, 3, 4, 5, 6, 7, 8,
        1, 2, 3, 4, 5, 6, 7, 8,
    ];

    let input: [u8; 16] = [
        0, 0xff, 0, 0, 0, 0xff, 0, 0,
        0, 0xff, 0, 0, 0, 0xff, 0, 0,
    ];

    let expected: [u8; 32] = [
        0xc5, 0x92, 0x55, 0x87, 0xca, 0x38, 0xaa, 0xc4,
        0x31, 0xe7, 0x2e, 0xed, 0x19, 0x72, 0x31, 0x93,
        0x51, 0x13, 0x96, 0xee, 0x67, 0xea, 0x8, 0x43,
        0xd7, 0x3c, 0x9e, 0xa3, 0x96, 0xd4, 0x83, 0x1f
    ];

    let mut results = [0u8; 32];

    chacha_hash(&input, &key, &mut results, 8);
    assert_eq!(results, expected);
}
