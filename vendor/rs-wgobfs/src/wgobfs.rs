
use crate::chacha_glue::chacha_hash;

const WG_HANDSHAKE_INIT: u8 = 1;
const WG_HANDSHAKE_RESP: u8 = 2;
const OBFS_WG_HANDSHAKE_INIT: u8 = 0x11;
const OBFS_WG_HANDSHAKE_RESP: u8 = 0x12;
const WG_DATA: u8 = 4;
const WG_MIN_LEN: usize = 32;
const MIN_RND_LEN: usize = 4;
const CHACHA_INPUT_SIZE: usize = 16;
pub const MAX_RND_LEN: usize = 32;
const WG_COOKIE_WORDS: usize = 4;
const MAX_RND_WORDS: usize = 8;

pub enum ForwardState {
    NFDrop,
    XTContinue,
}

struct ObfsBuf {
    chacha_in: [u8; CHACHA_INPUT_SIZE],
    chacha_out: [u8; MAX_RND_LEN],
    rnd: [u8; MAX_RND_LEN],
    rnd_len: usize,
}

fn random_drop_wg_keepalive(
    buf: &mut [u8],
    buf_len: usize,
    ob: &mut ObfsBuf,
    key: &[u8; 32],
) -> bool {
    if buf[0] != WG_DATA || buf_len != 32 {
        return false;
    }

    ob.chacha_in[0] = ob.chacha_in[0].wrapping_add(1);
    chacha_hash(&ob.chacha_in, key, &mut ob.chacha_out, 1);
    // assume the probability of a 1 byte PRN > 50 is 0.8
    if ob.chacha_out[0] > 50 {
        return true;
    } else {
        return false;
    }
}

fn get_prn_insert(ob: &mut ObfsBuf, key: &[u8; 32], min_len: usize, max_len: usize) -> u8 {
    let mut r: u8 = 0;
    loop {
        ob.chacha_in[0] = ob.chacha_in[0].wrapping_add(1);
        chacha_hash(&ob.chacha_in, key, &mut ob.rnd, MAX_RND_WORDS);
        for i in 0..MAX_RND_LEN {
            if ob.rnd[i] >= min_len as u8 && ob.rnd[i] <= max_len as u8 {
                r = ob.rnd[i];
                break;
            }
        }

        if r > 0 {
            break;
        }
    }

    ob.rnd_len = r as usize;
    return r;
}

fn obfs_mac2(
    buf: &mut [u8],
    data_len: usize,
    ob: &mut ObfsBuf,
    key: &[u8; 32],
) {
    let msg_type: u8 = buf[0];
    if msg_type == WG_HANDSHAKE_INIT && data_len == 148 {
        let mut mac2 = &mut buf[132..148];
        // highly unlikely the first 4 bytes of cookie are all zeros
        let np = u32::from_ne_bytes(mac2[0..4].try_into().unwrap());
        if np == 0 {
            ob.chacha_in[0] = ob.chacha_in[0].wrapping_add(1);
            chacha_hash(&ob.chacha_in, key, &mut mac2, WG_COOKIE_WORDS);
            // mark the packet as need restore mac2 upon receiving
            buf[0] |= 0x10;
        }
    } else if msg_type == WG_HANDSHAKE_RESP && data_len == 92 {
        let mut mac2 = &mut buf[76..92];
        let np = u32::from_ne_bytes(mac2[0..4].try_into().unwrap());
        if np == 0 {
            ob.chacha_in[0] = ob.chacha_in[0].wrapping_add(1);
            chacha_hash(&ob.chacha_in, key, &mut mac2, WG_COOKIE_WORDS);
            buf[0] |= 0x10;
        }
    }
}

fn restore_mac2(buf: &mut [u8]) {
    let zero_mac2: [u8; 16] = [0u8; 16];
    match buf[0] {
        OBFS_WG_HANDSHAKE_INIT => {
            let mac2 = &mut buf[132..148];
            mac2[..16].copy_from_slice(&zero_mac2[..16]);
        }
        OBFS_WG_HANDSHAKE_RESP => {
            let mac2 = &mut buf[76..92];
            mac2[..16].copy_from_slice(&zero_mac2[..16]);
        }
        _ => (),
    }

    buf[0] &= 0x0F;
}

pub(crate) fn obfs_udp_payload(
    buf: &mut [u8],
    wg_data_len: usize,
    key: &[u8; 32],
    rnd_len_out: &mut usize,
) -> ForwardState {
    if wg_data_len < WG_MIN_LEN || wg_data_len + MAX_RND_LEN > buf.len() {
        return ForwardState::NFDrop;
    }

    let mut ob = ObfsBuf {
        chacha_in: [0u8; CHACHA_INPUT_SIZE],
        chacha_out: [0u8; MAX_RND_LEN],
        rnd: [0u8; MAX_RND_LEN],
        rnd_len: 0,
    };

    /* Use 16th to 31st bytes of WG message as input of chacha.
     *
     * The 16th to 31st bytes is:
     *  - handshake initiation unencrypted_ephemeral (32 bytes starts at 8)
     *  - handshake response unencrypted_ephemeral (32 bytes starts at 12)
     *  - cookie nonce (24 bytes starts at 8)
     *  - data encrypted packet (var length starts at 16)
     *  - keepalive random poly1305 tag (16 bytes starts at 16)
     *
     *  Increment the first byte as counter to generate different PRN
     */
    ob.chacha_in[..CHACHA_INPUT_SIZE].copy_from_slice(&buf[16..16 + CHACHA_INPUT_SIZE]);

    /* Later will use the unchange 16th to 31st bytes to gernerate a PRN,
     * which XOR with first 16 bytes of WG. Peer will need generate an
     * identical PRN to recover the original WG.
     * Other PRNs will be generated with incremented counter.
     */
    ob.chacha_in[0] = ob.chacha_in[0].wrapping_add(42);

    if random_drop_wg_keepalive(buf, wg_data_len, &mut ob, key) {
        return ForwardState::NFDrop;
    }

    obfs_mac2(buf, wg_data_len, &mut ob, key);

    let max_rnd_len = if wg_data_len > 200 { 8 } else { MAX_RND_LEN };

    get_prn_insert(&mut ob, key, MIN_RND_LEN, max_rnd_len);
    // hopefully keep rnd_len in cache line without access the ob struct
    let rnd_len = ob.rnd_len;
    // append random bytes to WG packet
    buf[wg_data_len..wg_data_len + rnd_len].copy_from_slice(&ob.rnd[..rnd_len]);

    // Use PRN to XOR with the first 16 bytes of WG message. It has message
    // type, reserved field and counter. They look distinct.
    let chacha_in: &[u8; 16] = buf[16..32].try_into().expect("Slice is not 16 bytes long");
    chacha_hash(chacha_in, key, &mut ob.chacha_out, 5);
    // set the last byte of random as its length
    buf[wg_data_len + rnd_len - 1] = rnd_len as u8 ^ ob.chacha_out[16];
    for i in 0..16 {
        buf[i] ^= ob.chacha_out[i];
    }

    *rnd_len_out = rnd_len;
    return ForwardState::XTContinue;
}

pub(crate) fn unobfs_udp_payload(
    buf: &mut [u8],
    wg_data_len: usize,
    key: &[u8; 32],
    rnd_len_out: &mut usize,
) -> ForwardState {
    if wg_data_len < (WG_MIN_LEN + MIN_RND_LEN) {
        return ForwardState::NFDrop;
    }

    let mut buf_prn: [u8; MAX_RND_LEN] = [0u8; MAX_RND_LEN];

    // Same as obfuscate, generate the same PRN from 16th to 31st bytes of WG
    // message. Need it for restoring the first 16 bytes of WG message.
    let chacha_in: &[u8; 16] = buf[16..32].try_into().expect("Slice is not 16 bytes long");
    chacha_hash(chacha_in, key, &mut buf_prn, 5);

    // Restore the length of random padding. It is stored in the last byte of
    // obfuscated WG.
    buf[wg_data_len - 1] ^= buf_prn[16];
    let rnd_len = buf[wg_data_len - 1] as usize;
    if rnd_len == 0 || (rnd_len + WG_MIN_LEN) > wg_data_len {
        return ForwardState::NFDrop;
    }

    // restore the first 16 bytes of WG packet
    for i in 0..16 {
        buf[i] ^= buf_prn[i];
    }

    *rnd_len_out = rnd_len;
    restore_mac2(buf);

    return ForwardState::XTContinue;
}
