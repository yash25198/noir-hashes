use std::wrapping_add;
// SHA-512 compression function
#[no_predicates]
pub fn sha_c(msg: [u64; 16], hash: [u64; 8]) -> [u64; 8] {
    // noir-fmt:ignore
    let K= crate::constants::round_constants();
    let mut out_h: [u64; 8] = hash;
    let w = crate::schedule::sha_w(msg);
    for j in 0..80 {
        let out1 = wrapping_add(out_h[7], crate::operations::sha_bigma1(out_h[4]));
        let out2 = wrapping_add(
            out1,
            crate::operations::sha_ch(out_h[4], out_h[5], out_h[6]),
        );
        let t1 = wrapping_add(wrapping_add(out2, K[j]), w[j]);
        let t2 = wrapping_add(
            crate::operations::sha_bigma0(out_h[0]),
            crate::operations::sha_maj(out_h[0], out_h[1], out_h[2]),
        );
        out_h[7] = out_h[6];
        out_h[6] = out_h[5];
        out_h[5] = out_h[4];
        out_h[4] = wrapping_add(out_h[3], t1);
        out_h[3] = out_h[2];
        out_h[2] = out_h[1];
        out_h[1] = out_h[0];
        out_h[0] = wrapping_add(t1, t2);
    }

    out_h
}
// Convert 128-byte array to array of 16 u64s
pub fn msg_u8_to_u64(msg: [u8; 128]) -> [u64; 16] {
    let mut msg64: [u64; 16] = [0; 16];

    for i in 0..16 {
        let mut msg_field: Field = 0;
        for j in 0..8 {
            msg_field = msg_field * 256 + msg[128 - 8 * (i + 1) + j] as Field;
        }
        msg64[15 - i] = msg_field as u64;
    }

    msg64
}
