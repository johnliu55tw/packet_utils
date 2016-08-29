extern crate rand;
extern crate rustc_serialize;

extern crate packet_utils;

use std::error::Error;
use std::io::prelude::*;
use std::io::BufReader;
use std::fs;
use std::path::Path;
use self::rustc_serialize::hex::FromHex;
use packet_utils::*; 


fn create_random_bytes(size: usize) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::with_capacity(size);
    for _ in 0..buf.capacity() {
        buf.push(rand::random::<u8>());
    }
    buf
}

fn read_test_data(path: &Path) -> (Vec<u8>, Vec<Vec<u8>>) {
    let mut raw_data: Vec<u8> = Vec::new();
    let mut correct_data: Vec<Vec<u8>> = Vec::new();
    let mut file = match fs::File::open(path) {
        Err(e) => panic!("could not open {}: {}", path.display(),
                                                  e.description()),
        Ok(file) => BufReader::new(file),
    };

    let mut correct_flag = false;
    loop {
        let mut line = String::new();
        match file.read_line(&mut line) {
            Err(e) => panic!("could not open {}: {}", path.display(),
                                                      e.description()),
            Ok(size) => match size {
                0 => break,
                size => size,
            }
        };

        if line.starts_with("# CorrectData") {
            correct_flag = true;
            continue;
        }
        else if line.starts_with("#") {
            correct_flag = false;
            continue;
        }
        else {
            match correct_flag {
                false => {
                    raw_data.append(&mut line.from_hex().unwrap());
                },
                true => {
                    raw_data.append(&mut line.from_hex().unwrap());
                    correct_data.push(line.from_hex().unwrap());
                },
            }
        }
    }
    (raw_data, correct_data)
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
    assert!(has_valid_checksum(&buf, ChecksumType::XOR{offset: 0}));
}

#[test]
fn test_valid_checksum_add() {
    let mut buf: Vec<u8> = vec![0xFF, 0xFE, 0x86, 0x11, 0xD9];
    // Checksum = 0x36D
    buf.push(0x03);
    buf.push(0x6D);
    assert!(has_valid_checksum(&buf,
                               ChecksumType::ADD{size: 2,
                                                 offset: 0,
                                                 endian: Endian::Big}));

    let mut buf: Vec<u8> = vec![0xFF, 0xFE, 0x86, 0x11, 0xD9];
    buf.push(0x6D);
    buf.push(0x03);
    assert!(has_valid_checksum(&buf,
                               ChecksumType::ADD{size: 2,
                                                 offset: 0,
                                                 endian: Endian::Little}));
}

#[test]
fn test_find_valid_packets() {
    let paths = fs::read_dir("./resources/test_data").unwrap();
    for path in paths {
        let filepath = path.unwrap().path();
        let (raw_data, correct_data) = read_test_data(&filepath);
        let header = "73 6E 70".from_hex().unwrap();
        let (valid_packets, remained) = find_valid_packets(&raw_data,
                           &header,
                           4,
                           6,
                           ChecksumType::XOR{offset: 0});
        assert_eq!(correct_data, valid_packets);
    }
}
