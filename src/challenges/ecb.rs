use crate::challenges;
use challenges::common::{clean_duplicates, detect_encryption_ecb_or_cbc, Mode};
use challenges::oracles::encrypt_ecb_with_secret_appended;
use std::collections::HashMap;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecb_encryption_challenge() {
        let secret = break_encrypt_ecb_with_secret_appended().unwrap();
        assert_eq!(String::from_utf8(secret).unwrap(), "Rollin' in my 5.");
    }
    #[test]
    fn test_hard_ecb_encryption_challenge() {
        let secret = break_encrypt_ecb_with_secret_appended_and_random_prepended().unwrap();
        assert_eq!(String::from_utf8(secret).unwrap(), "Rollin' in my 5.");
    }
    #[test]
    fn test_detect_128_ecb() {
        let decoded_data: Vec<Vec<u8>> =
            include_str!("../../resources/cryptopals_set1_challenge8.txt")
                .split("\n")
                .collect::<Vec<&str>>()
                .iter()
                .filter_map(|s| {
                    let decoded = hex::decode(s).unwrap();
                    if decoded.len() > 0 {
                        Some(decoded)
                    } else {
                        None
                    }
                })
                .collect();
        let decoded_data_view: Vec<&[u8]> = decoded_data.iter().map(|v| &v[..]).collect();
        let detected_ecb_indexes = detect_128_ecb(&decoded_data_view[..]);

        assert_eq!(detected_ecb_indexes.len(), 1);
    }
}

// identifies from a list of blobs which of them has been encrypted using ecb
// returns the indexes of the ecb encrypted blobs
pub fn detect_128_ecb(encrypted_blobs: &[&[u8]]) -> Vec<usize> {
    let mut ecb_blob_indexes = Vec::new();
    for (i, &blob) in encrypted_blobs.iter().enumerate() {
        let mut is_ecb = false;

        let mut blob_chunks = blob.chunks(16).collect::<Vec<&[u8]>>();
        blob_chunks.sort();

        let last_chunk: &[u8] = blob_chunks.iter().last().unwrap();
        let one_before_last_chunk: &[u8] =
            blob_chunks.split_last().unwrap().1.iter().last().unwrap();
        for pair_chunks in blob_chunks.chunks_exact(2) {
            if pair_chunks[0] == pair_chunks[1] {
                is_ecb = true;
            }
        }
        if one_before_last_chunk == last_chunk {
            is_ecb = true;
        }

        if is_ecb {
            ecb_blob_indexes.push(i);
        }
    }

    return ecb_blob_indexes;
}

pub fn break_encrypt_ecb_with_secret_appended() -> Option<Vec<u8>> {
    let test_input = [b'A'; 32 * 10];
    let encryption_output = encrypt_ecb_with_secret_appended(&test_input);
    let mode = detect_encryption_ecb_or_cbc(&encryption_output[..]);

    if mode != Mode::Ecb {
        None
    } else {
        let mut secret: Vec<u8> = Vec::new();
        let block_size = get_block_size(encrypt_ecb_with_secret_appended)?;
        for i in 0..encrypt_ecb_with_secret_appended(&[]).len() / block_size {
            secret.append(&mut break_block(
                i,
                block_size,
                &secret[..],
                encrypt_ecb_with_secret_appended,
                0,
            ));
        }

        Some(clean_duplicates(&secret[..]))
    }
}

// this function assumes there's random prepended whose len > 0
fn break_block(
    block_index: usize,
    block_size: usize,
    earlier_blocks_discovered: &[u8],
    encryption_method: impl Fn(&[u8]) -> Vec<u8>,
    dont_care_prepended_length: usize,
) -> Vec<u8> {
    let mut block_decrypted_bytes = Vec::new();
    let mut initial_amount = 0;
    if dont_care_prepended_length % block_size != 0 {
        initial_amount = block_size - (dont_care_prepended_length % block_size);
    }
    let relevant_block_start = (dont_care_prepended_length as f32 / 16.0).ceil() as usize * 16;
    for i in 1..block_size + 1 {
        let encrypted_oracle_block = encryption_method(
            &[
                earlier_blocks_discovered,
                &vec![b'A'; initial_amount + (block_size - i) as usize],
            ]
            .concat()[..],
        );
        let mut last_byte_dict = HashMap::new();
        for byte in b'\n'..b'~' {
            let encrypted_output = encryption_method(
                &[
                    earlier_blocks_discovered,
                    &vec![b'A'; initial_amount + (block_size - i) as usize],
                    &block_decrypted_bytes[..],
                    &[byte],
                ]
                .concat()[..],
            );

            last_byte_dict.insert(
                encrypted_output
                    [relevant_block_start..relevant_block_start + block_size * (block_index + 1)]
                    .to_vec(),
                byte as u8,
            );
        }

        block_decrypted_bytes.push(
            *last_byte_dict
                .get(
                    &encrypted_oracle_block[relevant_block_start
                        ..relevant_block_start + block_size * (block_index + 1)]
                        .to_vec(),
                )
                .unwrap(),
        );
    }

    block_decrypted_bytes
}

fn get_block_size(encryption_method: fn(&[u8]) -> Vec<u8>) -> Option<usize> {
    // 128, 192 or 256 bits
    const BLOCK_OPTIONS_LEN: usize = 3;
    const BLOCK_OPTIONS: [usize; BLOCK_OPTIONS_LEN] = [16, 24, 32];

    let encrypted_bytes = encryption_method(&[b'A'; BLOCK_OPTIONS[BLOCK_OPTIONS_LEN - 1]]);
    for i in BLOCK_OPTIONS {
        let mut chunks_iter = encrypted_bytes.chunks(i);
        let first_chunk = chunks_iter.next();
        let second_chunk = chunks_iter.next();

        if first_chunk == second_chunk {
            return Some(i);
        }
    }
    None
}

pub fn break_encrypt_ecb_with_secret_appended_and_random_prepended() -> Option<Vec<u8>> {
    /*
    how many A's do I need to get 2 identical blocks?

    this amount % 16 leads to the random prefix size I need to complement for a block.

    then I do the same process - but instead of starting with 15 A's, I'll start with:
    (random_complement_to_block + 15) A's
    */
    use rand::prelude::*;
    let mut rng = rand::thread_rng();
    let random_prepended: Vec<u8> = (1..rand::random::<u8>())
        .map(|_| rng.gen_range(0..u8::MAX))
        .collect();

    let encryption_method =
        |data: &[u8]| encrypt_ecb_with_secret_appended(&[&random_prepended[..], data].concat());

    let random_length = get_random_size(encryption_method, 16).unwrap();
    let mut secret: Vec<u8> = Vec::new();
    for i in 0..encryption_method(&[]).len() / 16 {
        secret.append(&mut break_block(
            i,
            16,
            &secret[..],
            encryption_method,
            random_length,
        ));
    }

    Some(clean_duplicates(&secret[..]))
}

fn get_random_size(
    encryption_method: impl Fn(&[u8]) -> Vec<u8>,
    block_size: usize,
) -> Option<usize> {
    for i in 0..block_size {
        let output = encryption_method(&vec![b'A'; block_size * 2 + i]);
        let mut chunks_iter = output.chunks(block_size);
        let mut last_chunk = chunks_iter.next().unwrap();
        let mut fully_random_blocks_count = None;

        for (last_chunk_index, chunk) in chunks_iter.enumerate() {
            if chunk == last_chunk {
                if last_chunk_index == 0 {
                    fully_random_blocks_count = Some(0);
                } else {
                    fully_random_blocks_count = Some(last_chunk_index - 1);
                }
                break;
            }

            last_chunk = chunk;
        }

        if fully_random_blocks_count.is_some() {
            return Some(block_size - i + block_size * fully_random_blocks_count.unwrap());
        }
    }

    return None;
}
