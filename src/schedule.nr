use std::wrapping_add;

pub fn sha_w(msg: [u64; 16]) -> [u64; 80] {
    let mut w: [u64; 80] = [0; 80];

    for j in 0..16 {
        w[j] = msg[j];
    }

    for j in 16..80 {
        w[j] = wrapping_add(
            wrapping_add(crate::operations::sha_sigma1(w[j - 2]), w[j - 7]),
            wrapping_add(crate::operations::sha_sigma0(w[j - 15]), w[j - 16]),
        );
    }
    w
}
