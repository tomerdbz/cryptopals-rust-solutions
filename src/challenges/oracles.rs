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

    #[test]
    fn test_cbc_padding_oracle() {
        let (ciphertext, iv) = cbc_padding_oracle_ciphertext_generator();

        assert!(cbc_padding_oracle_ciphertext_verifier(&ciphertext, &iv[..]))
    }
}

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

pub struct UrlStringInputGenerator<'a> {
    encryption_method: &'a dyn Fn(&[u8], &[u8]) -> Vec<u8>,
    decryption_method: &'a dyn Fn(&[u8], &[u8]) -> Vec<u8>,
}

impl<'a> UrlStringInputGenerator<'a> {
    pub fn new_symmetric(
        apply_method: &'a dyn Fn(&[u8], &[u8]) -> Vec<u8>,
    ) -> UrlStringInputGenerator {
        UrlStringInputGenerator {
            encryption_method: apply_method,
            decryption_method: apply_method,
        }
    }

    pub fn new_asymmetric(
        encryption_method: &'a dyn Fn(&[u8], &[u8]) -> Vec<u8>,
        decryption_method: &'a dyn Fn(&[u8], &[u8]) -> Vec<u8>,
    ) -> UrlStringInputGenerator<'a> {
        UrlStringInputGenerator {
            encryption_method,
            decryption_method,
        }
    }

    pub fn generate(&self, userdata: &[u8]) -> Vec<u8> {
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
        let mut plaintext = prepend.to_vec();
        plaintext.append(&mut quote(userdata));
        plaintext.append(&mut append.to_vec());
        AES_KEY.with(|aes_key| (self.encryption_method)(&plaintext[..], aes_key))
    }

    pub fn is_admin(
        &self,
        ciphertext: &[u8],
        verify_string: bool,
    ) -> Result<bool, DecryptionError> {
        let plaintext = AES_KEY.with(|aes_key| (self.decryption_method)(&ciphertext[..], aes_key));

        if verify_string {
            for byte in &plaintext {
                if *byte > 127 {
                    return Err(DecryptionError {
                        invalid_plaintext: plaintext,
                    });
                }
            }

            return Ok(String::from_utf8(plaintext)
                .unwrap()
                .contains(";admin=true;"));
        }
        Ok(String::from_utf8_lossy(&plaintext).contains(";admin=true;"))
    }
}
#[derive(Debug, PartialEq, Clone)]
pub struct DecryptionError {
    pub invalid_plaintext: Vec<u8>,
}
use std::error::Error;
use std::fmt;

impl fmt::Display for DecryptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "High ascii bytes were detected. output is:\n{:?}",
            self.invalid_plaintext
        )
    }
}

impl Error for DecryptionError {}

pub fn cbc_padding_oracle_ciphertext_generator() -> (Vec<u8>, Vec<u8>) {
    use rand::prelude::*;
    let mut rng = rand::thread_rng();

    let strings_pool = [
        "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
        "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
        "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
        "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
        "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
        "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
        "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
        "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
        "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
        "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
    ];

    let chosen_string = strings_pool[rng.gen_range(0..strings_pool.len())];

    let iv: Vec<u8> = (0..16).map(|_| rng.gen_range(0..256) as u8).collect();

    AES_KEY.with(|aes_key| {
        (
            aes::encrypt_cbc_ecb_128_bit(&base64::decode(chosen_string).unwrap(), aes_key, &iv),
            iv,
        )
    })
}

pub fn cbc_padding_oracle_ciphertext_verifier(ciphertext: &[u8], iv: &[u8]) -> bool {
    match AES_KEY.with(|aes_key| aes::decrypt_cbc_ecb_128_bit(ciphertext, aes_key, iv)) {
        Ok(_) => true,
        Err(_) => false,
    }
}

use crate::ctr;

pub fn get_key() -> &'static std::thread::LocalKey<[u8; 16]> {
    &AES_KEY
}

pub fn ctr_edit_api(ciphertext: &[u8], offset: usize, newtext: &[u8]) -> Vec<u8> {
    AES_KEY.with(|aes_key| ctr::edit(ciphertext, aes_key, offset, newtext).unwrap())
}

pub fn ctr_ciphertext() -> Vec<u8> {
    let plaintext = base64::decode(
        include_str!("../../resources/cryptopals_set4_challenge25.txt").replace("\n", ""),
    )
    .unwrap();
    AES_KEY.with(|aes_key| ctr::apply_ctr(&plaintext[..], aes_key).unwrap())
}

pub fn sucessive_ctr() -> Vec<Vec<u8>> {
    AES_KEY.with(|aes_key| {
        let strings_pool = [
            "VG8gcGxlYXNlIGEgY29tcGFuaW9u",
            "RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
            "SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
            "SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
            "Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
            "RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
            "T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
            "T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
            "UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
            "QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
            "T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
            "QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
            "QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
            "QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
            "QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
            "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
            "VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
            "SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
            "SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
            "VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
            "V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
            "V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
            "U2hlIHJvZGUgdG8gaGFycmllcnM/",
            "VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
            "QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
            "VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
            "V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
            "SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
            "U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
            "U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
            "VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
            "QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
            "SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
            "VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
            "WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
            "SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
            "SW4gdGhlIGNhc3VhbCBjb21lZHk7",
            "SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
            "VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
            "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
        ];

        let mut output = Vec::new();
        for s in strings_pool {
            output.push(ctr::apply_ctr(&base64::decode(s).unwrap(), aes_key).unwrap());
        }

        output
    })
}
