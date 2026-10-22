// Copyright (c) 2026 The Bitcoin PoCX developers
// Distributed under the MIT software license; see COPYING.
// Validate kernel fixture qualities with independent Rust scalar plot generation.
use pocx_hashlib::{calculate_scoop, calculate_quality_from_height};
use pocx_hashlib::noncegen_32::generate_nonces_32;
use pocx_hashlib::quality_32::find_best_quality_32;
use pocx_hashlib::noncegen_common::NONCE_SIZE;

fn bytes<const N: usize>(hex: &str) -> [u8; N] {
    assert_eq!(hex.len(), 2 * N);
    std::array::from_fn(|i| u8::from_str_radix(&hex[2*i..2*i+2], 16).unwrap())
}

fn main() {
    let path = std::env::args().nth(1).expect("Proof input file required");
    let input = std::fs::read_to_string(path).unwrap();
    let mut count = 0;
    let mut buffer = vec![0u8; NONCE_SIZE];
    for line in input.lines() {
        let fields: Vec<_> = line.split(',').collect();
        assert_eq!(fields.len(), 7);
        let gensig = bytes::<32>(fields[0]);
        let account = bytes::<20>(fields[1]);
        let seed = bytes::<32>(fields[2]);
        let nonce = fields[3].parse::<u64>().unwrap();
        let height = fields[4].parse::<u64>().unwrap();
        let compression = fields[5].parse::<u8>().unwrap();
        let expected = fields[6].parse::<u64>().unwrap();
        assert_eq!(compression, 1); // Bounded two-nonce scalar fixture verification.
        let scoop = calculate_scoop(height, &gensig);
        let mut compressed = [0u8; 64];
        let lanes = 1u64 << compression;
        for lane in 0..lanes {
            let (source_scoop, position) = if lane % 2 == 0 {
                (scoop, nonce % 4096)
            } else {
                (nonce % 4096, scoop)
            };
            let source_nonce = ((nonce / 4096) * lanes + lane) * 4096 + position;
            generate_nonces_32(&mut buffer, 0, &account, &seed, source_nonce, 1);
            let start = source_scoop as usize * 64;
            for i in 0..64 { compressed[i] ^= buffer[start + i]; }
        }
        let quality = find_best_quality_32(&compressed, 1, &gensig).0;
        assert_eq!(quality, expected, "fixture proof {} height {}", count, height);
        assert_eq!(quality, calculate_quality_from_height(&account, &seed, nonce, compression, height, &gensig).unwrap());
        count += 1;
    }
    assert_eq!(count, 207);
    println!("Verified {count} kernel fixture proofs using Rust scalar and optimized APIs");
}
