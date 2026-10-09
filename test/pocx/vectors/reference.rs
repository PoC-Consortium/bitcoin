// Copyright (c) 2026 The Bitcoin PoCX developers
// Distributed under the MIT software license; see COPYING.
// Offline fixture generator. Uses the separate Rust PoCX implementation, never
// the Bitcoin PoCX C++ implementation whose outputs these fixtures will check.
use pocx_hashlib::{calculate_scoop, calculate_quality_from_height};
use pocx_hashlib::noncegen_32::generate_nonces_32;
use pocx_hashlib::quality_32::find_best_quality_32;
use pocx_hashlib::noncegen_common::NONCE_SIZE;
use sha2::{Digest, Sha256};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    let nonces: [u64; 8] = [0, 4095, 4096, 8191, (1 << 32) + 17, (1 << 48) + 33, 131071, 0x123456789ab];
    let heights: [u64; 8] = [1, 2, 73, 74, 500, 32768, 1000000, 2147483647];
    let compressions: [u8; 8] = [1, 1, 2, 2, 3, 3, 7, 7];
    let targets: [u64; 8] = [1, 36650387592, 1 << 32, 1 << 63, 123456789, u64::MAX, 36650387592, 1];
    println!("[");
    for index in 0..8 {
        let account: [u8; 20] = std::array::from_fn(|j| (index * 17 + 3 + j) as u8);
        let seed: [u8; 32] = std::array::from_fn(|j| (index * 13 + 7 + 5 * j) as u8);
        let gensig: [u8; 32] = std::array::from_fn(|j| (index * 29 + 11 + 7 * j) as u8);
        let nonce = nonces[index];
        let height = heights[index];
        let compression = compressions[index];
        let target = targets[index];
        let scoop = calculate_scoop(height, &gensig);
        let mut buffer = vec![0u8; NONCE_SIZE];
        generate_nonces_32(&mut buffer, 0, &account, &seed, nonce, 1);
        let nonce_sha256 = hex(&Sha256::digest(&buffer));

        // Explicit scalar compressed-scoop assembly; cross-check the separate
        // Rust library's public optimized proof API below.
        let mut compressed_scoop = [0u8; 64];
        let count = 1u64 << compression;
        for lane in 0..count {
            let (source_scoop, position) = if lane % 2 == 0 {
                (scoop, nonce % 4096)
            } else {
                (nonce % 4096, scoop)
            };
            let source_nonce = ((nonce / 4096) * count + lane) * 4096 + position;
            generate_nonces_32(&mut buffer, 0, &account, &seed, source_nonce, 1);
            let start = source_scoop as usize * 64;
            for j in 0..64 {
                compressed_scoop[j] ^= buffer[start + j];
            }
        }
        let quality = find_best_quality_32(&compressed_scoop, 1, &gensig).0;
        assert_eq!(quality, calculate_quality_from_height(&account, &seed, nonce, compression, height, &gensig).unwrap());
        println!("{{\"account\":\"{}\",\"seed\":\"{}\",\"generation_signature\":\"{}\",\"nonce\":{},\"height\":{},\"compression\":{},\"base_target\":{},\"scoop\":{},\"compressed_scoop\":\"{}\",\"nonce_sha256\":\"{}\",\"quality\":{},\"raw_deadline\":{}}}{}",
            hex(&account), hex(&seed), hex(&gensig), nonce, height, compression, target, scoop,
            hex(&compressed_scoop), nonce_sha256, quality, quality / target,
            if index == 7 { "" } else { "," });
    }
    println!("]");
}
