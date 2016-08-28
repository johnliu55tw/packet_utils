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

#[test]
fn pri_test_bytes_to_uint() {
    let buf: [u8; 4] = [0xFF, 0xEE, 0x11, 0xDD];
    assert_eq!(buf_to_uint(&buf, Endian::Big), 0xFFEE11DDu64);
    assert_eq!(buf_to_uint(&buf, Endian::Little), 0xDD11EEFFu64);
}

pub enum Endian {
    Big,
    Little,
}

pub enum ChecksumType {
    XOR,
    ADD{size: u32, endian: Endian},
}

pub fn checksum_xor(buf: &[u8]) -> u8 {
    buf.iter().fold(0, |acc, &x| acc ^ x)
}

pub fn checksum_add(buf: &[u8], size: u32) -> u64 {
    buf.iter().fold(0, |acc: u64, &x| acc + x as u64) & (256u64.pow(size as u32) - 1)
}

pub fn has_valid_checksum(buf: &[u8],
                          offset: usize,
                          chk_type: ChecksumType) -> bool {
    match chk_type {
        ChecksumType::XOR => {
            checksum_xor(&buf[offset..buf.len()-1]) == buf[buf.len()-1]
        },
        ChecksumType::ADD{size, endian} => {
            let last_idx = buf.len() - size as usize;
            let checksum = checksum_add(&buf[offset..last_idx], size);
            checksum == buf_to_uint(&buf[last_idx..], endian)
        }
    }
}

pub fn find_valid_packets<'a>(buf: &'a[u8],
                              header: &'a[u8],
                              length_idx: usize,
                              length_off: usize,
                              chk_type: ChecksumType) -> Vec<&'a[u8]> {

    let mut valid_packets: Vec<&'a[u8]> = Vec::new();
    loop {

    valid_packets
}


#[cfg(test)]
mod tests {
    extern crate rand;
    extern crate rustc_serialize;
    use self::std::error::Error;
    use self::std::io::prelude::*;
    use self::std::path::Path;
    use self::rustc_serialize::hex::{ToHex, FromHex};
    use super::*;

    fn create_random_bytes(size: usize) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::with_capacity(size);
        for _ in 0..buf.capacity() {
            buf.push(rand::random::<u8>());
        }
        buf
    }

    #[test]
    fn test_checksum_xor() {
        let buf = create_random_bytes(100);
        let mut checksum_correct: u8 = 0;
        for elem in &buf {
            checksum_correct ^= *elem;
        }
        assert_eq!(checksum_correct, checksum_xor(&buf));
    }

    #[test]
    fn test_checksum_add() {
        let buf = create_random_bytes(100);
        let mut checksum_correct: u64 = 0;
        for elem in &buf {
            checksum_correct += *elem as u64;
        }
        checksum_correct &= 0xFFFF;
        assert_eq!(checksum_correct, checksum_add(&buf, 2));
    }

    #[test]
    fn test_valid_checksum_xor() {
        let mut buf = create_random_bytes(100);
        let mut checksum_correct: u8 = 0;
        for elem in &buf {
            checksum_correct ^= *elem;
        }
        buf.push(checksum_correct);
        assert!(has_valid_checksum(&buf, 0, ChecksumType::XOR));
    }

    #[test]
    fn test_valid_checksum_add() {
        let mut buf: Vec<u8> = vec![0xFF, 0xFE, 0x86, 0x11, 0xD9];
        // Checksum = 0x36D
        buf.push(0x03);
        buf.push(0x6D);
        assert!(has_valid_checksum(&buf,
                                   0,
                                   ChecksumType::ADD{size: 2, endian: Endian::Big}));

        let mut buf: Vec<u8> = vec![0xFF, 0xFE, 0x86, 0x11, 0xD9];
        buf.push(0x6D);
        buf.push(0x03);
        assert!(has_valid_checksum(&buf,
                                   0,
                                   ChecksumType::ADD{size: 2, endian: Endian::Little}));
    }

    #[test]
    fn test_find_valid_packets() {
        /* Data format index:
         * Header: 0 ~ 2
         * Packet Type: 3
         * Length: 4
         * Data: 5 ~ Length + 4
         * Chksum: Length + 5 ~ Length +6
         */
        let mut data: Vec<u8> = Vec::new();
        let header: [u8; 3] = [0x73, 0x61, 0x70];
        let payload: [u8; 5] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
        data.extend_from_slice(&header);
        data.push(0x80);
        data.push(0x05);
        data.extend_from_slice(&payload);
        data.push(0x05);
        data.push(0xC5);
        let found = find_valid_packets(&data, &header, 4, 0,
                        ChecksumType::ADD{size: 2, endian: Endian::Little});
        assert_eq!(found[0][..], data[..]);
    }
}
