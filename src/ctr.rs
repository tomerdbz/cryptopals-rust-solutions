#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_number_to_bit_string() {
        assert_eq!(
            Counter::new(2).to_bit_string::<byteorder::LittleEndian>(0),
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00"
        );
    }

    #[test]
    fn test_apply_ctr() {
        assert_eq!(
            String::from_utf8(
                apply_ctr(
                    &base64::decode(
                        "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==",
                    )
                    .unwrap(),
                    b"YELLOW SUBMARINE",
                )
                .unwrap(),
            )
            .unwrap(),
            "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "
        );
    }

    #[test]
    fn test_apply_ctr_encrypt_decrypt() {
        const DATA: &[u8] = b"Hello? is it my you're looking for?";
        const KEY: &[u8; 16] = b"YELLOW SUBMARINE";
        let ciphertext = apply_ctr(DATA, KEY).unwrap();
        let plaintext = apply_ctr(&ciphertext, KEY).unwrap();
        assert_eq!(plaintext, DATA);
    }

    #[test]
    fn test_ctr_edit() {
        const DATA: &[u8] = b"Hello? is it my you're looking for?";
        const KEY: &[u8; 16] = b"YELLOW SUBMARINE";
        let ciphertext = apply_ctr(DATA, KEY).unwrap();
        let new_ciphertext =
            edit(&ciphertext[..], KEY, 5, b"! it is me you're looking for!").unwrap();
        let plaintext = apply_ctr(&new_ciphertext[..], KEY).unwrap();
        assert_eq!(plaintext, b"Hello! it is me you're looking for!");
    }
}

use crate::aes;
use crate::error::Res;
use crate::xor;
use byteorder::{ByteOrder, LittleEndian};

pub fn edit(ciphertext: &[u8], key: &[u8], offset: usize, newtext: &[u8]) -> Option<Vec<u8>> {
    let mut edited_ciphertext = ciphertext.to_vec();
    if offset.checked_add(newtext.len()).unwrap() > ciphertext.len() {
        None
    } else {
        let initial_block_counter = offset / 16;
        let ending_block_counter = (offset + newtext.len()) / 16;
        let ctr_keystream: Vec<u8> = (initial_block_counter..=ending_block_counter)
            .map(|c| {
                aes::encrypt_aes_128_ecb(&Counter::new(c).to_bit_string::<LittleEndian>(0), key)
                    .unwrap()
            })
            .reduce(|a, b| [a, b].concat())
            .unwrap();

        for (i, b) in newtext.iter().enumerate() {
            let key_byte = ctr_keystream[offset % 16 + i];
            edited_ciphertext[offset + i] = b ^ key_byte;
        }

        Some(edited_ciphertext)
    }
}

pub fn apply_ctr(data: &[u8], key: &[u8]) -> Res<Vec<u8>> {
    let mut output = Vec::new();
    for (counter, block) in data.chunks(16).enumerate() {
        let keystream_for_block =
            aes::encrypt_aes_128_ecb(&Counter::new(counter).to_bit_string::<LittleEndian>(0), key)?;

        output.append(&mut xor::apply_repeating_xor(block, &keystream_for_block));
    }

    Ok(output)
}

struct Counter {
    counter: usize,
}

impl Counter {
    fn new(counter: usize) -> Counter {
        Counter { counter }
    }

    fn to_bit_string<E>(&self, nonce: usize) -> Vec<u8>
    where
        E: ByteOrder,
    {
        let mut nonce_correct_endianity = [0; 8];
        E::write_u64(&mut nonce_correct_endianity, nonce as u64);
        let mut n_correct_endianity = [0; 8];
        E::write_u64(&mut n_correct_endianity, self.counter as u64);
        [nonce_correct_endianity, n_correct_endianity].concat()
    }
}
