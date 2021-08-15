use crate::{aes, challenges, padding};
use aes::encrypt_aes_128_ecb;
use aes::encrypt_cbc_ecb_128_bit;
use challenges::common::Mode;

#[cfg(test)]
mod tests {
    // TODO - make this an integration test
    use crate::challenges;

    use super::*;
    use challenges::common::detect_encryption_ecb_or_cbc;

    #[test]
    fn test_cbc_ecb_oracle() {
        let data_to_encrypt =
            b"YELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINE_EH";
        for _ in 0..100 {
            let encrypted_data = wrap_with_random_and_encrypt_ecb_or_cbc(data_to_encrypt);
            assert_eq!(
                detect_encryption_ecb_or_cbc(&encrypted_data.0[..]),
                encrypted_data.1
            );
        }
    }
}

//pub fn encryption_oracle(data: &[u8]) -> (Vec<u8>, Mode) {
pub fn wrap_with_random_and_encrypt_ecb_or_cbc(data: &[u8]) -> (Vec<u8>, Mode) {
    use rand::prelude::*;
    let mut rng = rand::thread_rng();

    let aes_key: Vec<u8> = (0..16).map(|_| rng.gen_range(0..256) as u8).collect();

    let append_before: Vec<u8> = (0..rng.gen_range(5..10))
        .map(|_| rand::random::<u8>())
        .collect();
    let mut append_after: Vec<u8> = (0..rng.gen_range(5..10))
        .map(|_| rand::random::<u8>())
        .collect();

    let mut data_to_encrypt: Vec<u8> = append_before;
    data_to_encrypt.append(&mut data.to_vec());
    data_to_encrypt.append(&mut append_after);

    match rand::random::<bool>() {
        true => (
            encrypt_aes_128_ecb(&padding::pkcs7(data, 16).unwrap()[..], &aes_key[..]).unwrap(),
            Mode::Ecb,
        ),
        false => (
            encrypt_cbc_ecb_128_bit(
                data,
                &aes_key[..],
                &(0..16)
                    .map(|_| rng.gen_range(0..256) as u8)
                    .collect::<Vec<u8>>()[..],
            ),
            Mode::Cbc,
        ),
    }
}

thread_local!(static AES_KEY: [u8; 16] = rand::random());

pub fn encrypt_ecb_with_secret_appended(data: &[u8]) -> Vec<u8> {
    let mut append_after: Vec<u8> = base64::decode(
            "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK",
        ).unwrap();
    let mut data_to_encrypt: Vec<u8> = data.to_vec();
    data_to_encrypt.append(&mut append_after);
    AES_KEY.with(|aes_key| {
        if data_to_encrypt.len() % 16 != 0 {
            return aes::encrypt_aes_128_ecb(
                &padding::pkcs7(&data_to_encrypt[..], 16).unwrap()[..],
                &aes_key[..],
            )
            .unwrap();
        } else {
            return aes::encrypt_aes_128_ecb(&data_to_encrypt[..], &aes_key[..]).unwrap();
        }
    })
}

pub fn cbc_challenge_ciphertext_oracle(data: &[u8]) -> Vec<u8> {
    let prepend = b"comment1=cooking%20MCs;userdata=";
    let append = b";comment2=%20like%20a%20pound%20of%20bacon";

    let quote = |unescaped: &[u8]| {
        let mut escaped: Vec<u8> = Vec::new();
        for b in unescaped {
            if *b == b';' || *b == b'=' {
                escaped.push(b'"');
                escaped.push(*b);
                escaped.push(b'"');
            } else {
                escaped.push(*b);
            }
        }
        escaped
    };
    let mut to_encrypt = prepend.to_vec();
    to_encrypt.append(&mut quote(data));
    to_encrypt.append(&mut append.to_vec());
    AES_KEY.with(|aes_key| aes::encrypt_cbc_ecb_128_bit(&to_encrypt[..], aes_key, &[0; 16]))
}

pub fn cbc_challenge_decrypt_cipher_search_admin(data: &[u8]) -> bool {
    String::from_utf8_lossy(
        &AES_KEY.with(|aes_key| aes::decrypt_cbc_ecb_128_bit(data, aes_key, &[0; 16])),
    )
    .contains(";admin=true;")
}
