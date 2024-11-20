pub fn rotr64(a: u64, b: u8) -> u64 {
    (a >> b) + (a << (64 - b))
}

pub fn sha_ch(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (!x & z)
}

pub fn sha_maj(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (x & z) ^ (y & z)
}

pub fn sha_bigma0(x: u64) -> u64 {
    rotr64(x, 28) ^ rotr64(x, 34) ^ rotr64(x, 39)
}

pub fn sha_bigma1(x: u64) -> u64 {
    rotr64(x, 14) ^ rotr64(x, 18) ^ rotr64(x, 41)
}

pub fn sha_sigma0(x: u64) -> u64 {
    rotr64(x, 1) ^ rotr64(x, 8) ^ (x >> 7)
}

pub fn sha_sigma1(x: u64) -> u64 {
    rotr64(x, 19) ^ rotr64(x, 61) ^ (x >> 6)
}
