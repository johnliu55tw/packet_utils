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

pub fn checksum_xor(buf: &[u8]) -> u8 {
    buf.iter().fold(0, |acc, &x| acc ^ x)
}

pub fn checksum_add(buf: &[u8], size: u8) -> u64 {
    buf.iter().fold(0, |acc: u64, &x| acc + x as u64) & (256u64.pow(size as u32) - 1)
}

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
