use std::wrapping_add;

pub fn digest<let N: u32>(msg: [u8; N], msg_len: u32, iv: [u64; 8]) -> [u8; 64] {
    let mut msg_block: [u8; 128] = [0; 128];
    // noir-fmt:ignore
    let mut h: [u64; 8] = iv; // Initial hash values
    let mut c: [u64; 8] = [0; 8]; // Compression of current message block as sequence of u64
    let mut out_h: [u8; 64] = [0; 64]; // Digest as sequence of bytes
    let mut i: u64 = 0; // Message byte pointer
    for k in 0..N {
        // Populate msg_block
        if (k < msg_len) {
            msg_block[i] = msg[k];
            i = i + 1;
            if (i == 128) {
                // Enough to hash block
                c = crate::compress::sha_c(crate::compress::msg_u8_to_u64(msg_block), h);
                for j in 0..8 {
                    h[j] = wrapping_add(h[j], c[j]);
                }

                i = 0;
            }
        }
    }
    // Pad the rest such that we have a [u64; 2] block at the end representing the length
    // of the message, and a block of 1 0 ... 0 following the message (i.e. [1 << 7, 0, ..., 0]).
    msg_block[i] = 1 << 7;
    i += 1;
    // If i >= 113, there aren't enough bits in the current message block to accomplish this, so
    // the 1 and 0s fill up the current block, which we then compress accordingly.
    if i >= 113 {
        // Not enough bits (128) to store length. Fill up with zeros.
        if i < 128 {
            for _i in 113..128 {
                if i <= 127 {
                    msg_block[i] = 0;
                    i += 1;
                }
            }
        }
        c = crate::compress::sha_c(crate::compress::msg_u8_to_u64(msg_block), h);
        for j in 0..8 {
            h[j] = wrapping_add(h[j], c[j]);
        }

        i = 0;
    }

    let len = 8 * msg_len;
    let len_bytes: [u8; 16] = (len as Field).to_le_bytes();
    for _i in 0..128 {
        // In any case, fill blocks up with zeros until the last 128 (i.e. until i = 112).
        if i < 112 {
            msg_block[i] = 0;
            i += 1;
        } else if i < 128 {
            for j in 0..16 {
                msg_block[127 - j] = len_bytes[j];
            }
            i += 16; // Done.
        }
    }
    // Hash final padded block
    c = crate::compress::sha_c(crate::compress::msg_u8_to_u64(msg_block), h);
    for j in 0..8 {
        h[j] = wrapping_add(h[j], c[j]);
    }
    // Return final hash as byte array
    for j in 0..8 {
        let h_bytes: [u8; 8] = (h[7 - j] as Field).to_le_bytes();
        for k in 0..8 {
            out_h[63 - 8 * j - k] = h_bytes[k];
        }
    }

    out_h
}
