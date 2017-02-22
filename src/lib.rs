#[derive(Debug, Copy, Clone)]
pub enum Endian {
    Big,
    Little,
}

#[derive(Debug, Copy, Clone)]
pub enum ChecksumType {
    XOR{offset: usize},
    ADD{size: u8, offset: usize, endian: Endian},
}

/* Transform a vector of u8 into one u64 value */
fn buf_to_uint(buf: &[u8], endian: Endian) -> u64 {
    match endian {
        Endian::Big => {
            buf.iter().fold(0, |acc: u64, &x| (acc << 8) + x as u64)
        },
        Endian::Little => {
            let mut val: u64 = 0;
            for (idx, byte) in buf.iter().enumerate() {
                val += (*byte as u64) << (8 * idx);
            }
            val
        }
    }
}

/* Calculate the checksum from a vector of u8 by XOR method. */
pub fn checksum_xor(buf: &[u8]) -> u8 {
    buf.iter().fold(0, |acc, &x| acc ^ x)
}

/* Calculate the checksum from a vector of u8 by summing method.
 * The size of checksum (bytes) is requried.
 * */
pub fn checksum_add(buf: &[u8], size: u8) -> u64 {
    buf.iter().fold(0, |acc: u64, &x| acc + x as u64) & (256u64.pow(size as u32) - 1)
}

/* Verify if the given vector has valid checksum, which is calculated specified
 * by the user.
 */
pub fn has_valid_checksum(buf: &[u8],
                          chk_type: ChecksumType) -> bool {
    match chk_type {
        ChecksumType::XOR{offset} => {
            checksum_xor(&buf[offset..buf.len()-1]) == buf[buf.len()-1]
        },
        ChecksumType::ADD{size, offset, endian} => {
            let last_idx = buf.len() - size as usize;
            let checksum = checksum_add(&buf[offset..last_idx], size);
            checksum == buf_to_uint(&buf[last_idx..], endian)
        }
    }
}

/* Find valiad packet from vector of u8.
 * Args:
 *   buf: The buffer.
 *   header: The header bytes.
 *   len_idx: The index of the length byte in the packet.
 *   len_off: the length acquired from len_idx must be the whole length.
 *            If not, the len_off must be passed and will be added to the length
 *            acquired from len_idx.
 *   chk_type: The type of checksum.
 *
 * Return:
 *   valid_packets: A vector of valid packets in &[u8].
 *   remained_buf: The remaining buffer data
 */
pub fn find_valid_packets<'a>(buf: &'a[u8],
                              header: &'a[u8],
                              len_idx: usize,
                              len_off: usize,
                              chk_type: ChecksumType)
        -> (Vec<&'a[u8]>, &'a[u8]) {

    let buf_len = buf.len();
    let header_len = header.len();
    let mut valid_packets: Vec<&'a[u8]> = Vec::new();
    let mut remained_buf = buf;
    let mut curr_idx: usize = 0;
    let mut buf_iter = buf.iter();
    loop {
        /* Use the first byte from header to locate the beginning of packet.
         * Noted that the index returned by position() method if relative to
         * the current position of the iterator, so add 1 to curr_idx is
         * required in order to get the correct absolute index.
         */
        curr_idx += match buf_iter.position(|&x| x == header[0]) {
            None => break,
            Some(idx) => idx,
        };

        if buf_len - curr_idx < header_len {
            remained_buf = &buf[curr_idx..];
            break;
        }

        if !buf[curr_idx..].starts_with(header) {
            curr_idx += 1;
            continue;
        }

        if buf_len - curr_idx < len_idx + 1 {
            remained_buf = &buf[curr_idx..];
            break;
        }

        if buf_len - curr_idx < buf[curr_idx+len_idx] as usize+ len_off {
            curr_idx += 1;
            continue;
        }
        let packet_len = buf[curr_idx+len_idx] as usize + len_off;

        if !has_valid_checksum(&buf[curr_idx..curr_idx+packet_len], chk_type) {
            curr_idx += 1;
            continue;
        }

        valid_packets.push(&buf[curr_idx..curr_idx+packet_len]);
        // Review:
        // Need to find a away to move more than 1
        curr_idx += 1;

    }
    (valid_packets, remained_buf)
}
