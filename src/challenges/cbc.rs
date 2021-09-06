use crate::challenges;
use challenges::oracles;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aes;
    const IV: [u8; 16] = [0u8; 16];
    #[test]
    fn test_cbc_challenge_cant_put_admin() {
        let generator = oracles::UrlStringInputGenerator::new_asymmetric(
            &|plaintext, aes_key| aes::encrypt_cbc_ecb_128_bit(&plaintext[..], aes_key, &IV[..]),
            &|ciphertext, aes_key| {
                aes::decrypt_cbc_ecb_128_bit(&ciphertext[..], aes_key, &IV[..]).unwrap()
            },
        );

        let ciphertext = generator.generate(b"hello;admin=true");

        assert_eq!(generator.is_admin(&ciphertext[..], false).unwrap(), false);
    }

    #[test]
    fn test_cbc_challenge_make_admin() {
        let generator = oracles::UrlStringInputGenerator::new_asymmetric(
            &|plaintext, aes_key| aes::encrypt_cbc_ecb_128_bit(&plaintext[..], aes_key, &IV[..]),
            &|ciphertext, aes_key| {
                aes::decrypt_cbc_ecb_128_bit(&ciphertext[..], aes_key, &IV[..]).unwrap()
            },
        );

        let ciphertext =
            make_admin(&generator.generate(&find_suitable_userdata(&generator).unwrap()));

        assert_eq!(generator.is_admin(&ciphertext[..], false).unwrap(), true);
    }

    #[test]
    fn test_cbc_challenge_make_admin_with_key_equals_iv() {
        let generator = oracles::UrlStringInputGenerator::new_asymmetric(
            &|plaintext, aes_key| {
                oracles::get_key()
                    .with(|key| aes::encrypt_cbc_ecb_128_bit(&plaintext[..], aes_key, &key[..]))
            },
            &|ciphertext, aes_key| {
                oracles::get_key().with(|key| {
                    aes::decrypt_cbc_ecb_128_bit(&ciphertext[..], aes_key, &key[..]).unwrap()
                })
            },
        );

        let ciphertext = generator.generate(b"dontcare");

        let modified_ciphertext = [
            &ciphertext[..16],
            &[0u8; 16][..],
            &ciphertext[..16],
            &ciphertext[48..],
        ]
        .concat();

        let invalid_plaintext = generator
            .is_admin(&modified_ciphertext[..], true)
            .err()
            .unwrap()
            .invalid_plaintext;

        let discovered_iv: Vec<u8> = invalid_plaintext[..16]
            .iter()
            .zip(&invalid_plaintext[32..48])
            .map(|(&b1, &b2)| b1 ^ b2)
            .collect();
        oracles::get_key().with(|key| {
            assert_eq!(key, &discovered_iv[..]);
        });
    }

    #[test]
    fn test_cbc_challenge_padding_oracle() {
        let decrypted = cbc_challenge_break_padding_oracle();
        assert!(String::from_utf8(decrypted).is_ok());
    }
}

pub fn find_suitable_userdata(generator: &oracles::UrlStringInputGenerator) -> Option<Vec<u8>> {
    /*
    "comment1=cooking" "%20MCs;userdata=" "i_dont_care_yay_" "YadminXtrueY"

     FFFFFFFFFFFFFFFF   FFFFFFFFFFFFFFFF   FFFFFFFFFFFFFFFF   FFFFFFFFFFFFFFFF

    what should be in Y that one bit will change to ; (59d)
    answer ':'
    the lsb in ':' is 0 instead of 1 in ';'

    and what should be in X that one bit will change to = (61d)
    answer '<'
    the lsb in '<' is 0 instead of 1 in '='
       */
    use rand::prelude::*;
    let mut rng = rand::thread_rng();

    let mut userdata = None;

    while userdata.is_none() {
        // the dont cares must not contain = or ; or else the offsets will be broken because of quotes
        let prepend_dont_cares: Vec<u8> = (0..16).map(|_| rng.gen_range(0..b';' - 1)).collect();
        let candidate_userdata = [&prepend_dont_cares[..], b":admin<true:"].concat();
        let ciphertext = generator.generate(&candidate_userdata);
        let third_block_first_byte = ciphertext[16 * 2];
        let third_block_sixth_byte = ciphertext[16 * 2 + 6];
        let third_block_eleventh_byte = ciphertext[16 * 2 + 11];
        if third_block_first_byte % 2 == 1
            && third_block_sixth_byte % 2 == 1
            && third_block_eleventh_byte % 2 == 1
        {
            userdata = Some(candidate_userdata);
        }
    }
    userdata
}

pub fn make_admin(ciphertext: &[u8]) -> Vec<u8> {
    let mut modified_ciphertext = ciphertext.to_vec();
    let third_block_first_byte = ciphertext[16 * 2];
    let third_block_sixth_byte = ciphertext[16 * 2 + 6];
    let third_block_eleventh_byte = ciphertext[16 * 2 + 11];
    modified_ciphertext[16 * 2] = third_block_first_byte - 1;
    modified_ciphertext[16 * 2 + 6] = third_block_sixth_byte - 1;
    modified_ciphertext[16 * 2 + 11] = third_block_eleventh_byte - 1;

    return modified_ciphertext;
}

pub fn cbc_challenge_break_padding_oracle() -> Vec<u8> {
    let (ciphertext, iv) = oracles::cbc_padding_oracle_ciphertext_generator();

    let mut plaintext = Vec::new();

    let mut block_iter = ciphertext.chunks(16).peekable();
    let mut manipulation_block = iv.clone();
    let mut target_block = block_iter.next().unwrap();

    while block_iter.peek().is_some() {
        let mut plaintext_target_block = vec![0; 16];
        let mut ecb_decrypted_target_block = vec![0; 16];
        let mut has_bruteforced;
        let original_last_block = manipulation_block.clone();
        for reverse_offset in 1u8..16u8 + 1 {
            let bruteforcing_offset = 16 - reverse_offset as usize;
            has_bruteforced = false;

            for byte in 0..=u8::MAX {
                manipulation_block[bruteforcing_offset] = byte;
                if oracles::cbc_padding_oracle_ciphertext_verifier(
                    &target_block[..],
                    &manipulation_block[..],
                ) {
                    // most probably we got to a state where
                    // for each i in bruteforcing_offset..16
                    //      ((byte ^ decrypted_target_block[i]) == padding_byte)
                    // hence (decrypted_target_block[bruteforcing_offset] == (padding_byte ^ byte))
                    has_bruteforced = true;
                    let decrypted_byte = byte ^ reverse_offset;
                    ecb_decrypted_target_block[bruteforcing_offset] = decrypted_byte;
                    plaintext_target_block[bruteforcing_offset] = ecb_decrypted_target_block
                        [bruteforcing_offset]
                        ^ original_last_block[bruteforcing_offset];
                    // setup mainpulation_block for the next padding
                    let next_reverse_offset = reverse_offset + 1;
                    for i in bruteforcing_offset..16 {
                        manipulation_block[i] =
                            (next_reverse_offset) ^ ecb_decrypted_target_block[i];
                    }

                    break;
                }
            }
            if !has_bruteforced {
                panic!("Cannot find the padding...offset {}", bruteforcing_offset);
            }
        }

        plaintext.append(&mut plaintext_target_block);
        manipulation_block = target_block.to_vec();
        target_block = block_iter.next().unwrap();
    }

    plaintext
}
