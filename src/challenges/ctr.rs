use crate::challenges;
use crate::xor;
use challenges::oracles;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ctr_challenge_cant_put_admin() {
        let generator = oracles::UrlStringInputGenerator::new_symmetric(&|plaintext, aes_key| {
            ctr::apply_ctr(&plaintext[..], aes_key).unwrap()
        });

        let ciphertext = generator.generate(b"hello;admin=true");

        assert_eq!(generator.is_admin(&ciphertext[..], false).unwrap(), false);
    }

    #[test]
    fn test_ctr_challenge_make_admin() {
        let generator = oracles::UrlStringInputGenerator::new_symmetric(&|plaintext, aes_key| {
            ctr::apply_ctr(&plaintext[..], aes_key).unwrap()
        });

        let ciphertext = generator.generate(b"hello1admin8true");
        const USERDATA_EQUALS_INDEX: usize = 11;
        const USERDATA_SEMICOLON_INDEX: usize = 5;
        let modified_ciphertext = make_admin(
            &ciphertext[..],
            b'1',
            b'8',
            USERDATA_SEMICOLON_INDEX,
            USERDATA_EQUALS_INDEX,
        );

        assert_eq!(
            generator.is_admin(&modified_ciphertext[..], false).unwrap(),
            true
        );
    }

    #[test]
    fn test_break_sucessive_ctr() {
        assert!(break_sucessive_ctr_statistically());
    }
    #[test]
    fn test_break_aes_random_rw_ctr() {
        assert_eq!(
            break_aes_random_rw_ctr(),
            base64::decode(
                include_str!("../../resources/cryptopals_set4_challenge25.txt").replace("\n", ""),
            )
            .unwrap()
        )
    }
}
use crate::ctr;

pub fn make_admin(
    ciphertext: &[u8],
    userdata_semicolon_placeholder: u8,
    userdata_equals_placeholder: u8,
    userdata_semicolon_index: usize,
    userdata_equals_index: usize,
) -> Vec<u8> {
    const PREFIX_LEN: usize = 32;

    let text_equals_index: usize = PREFIX_LEN + userdata_equals_index;
    let text_semicolon_index: usize = PREFIX_LEN + userdata_semicolon_index;
    let key_byte_equals = userdata_equals_placeholder ^ ciphertext[text_equals_index];
    let key_byte_semicolon = userdata_semicolon_placeholder ^ ciphertext[text_semicolon_index];

    let mut modified_ciphertext = ciphertext.to_vec();
    modified_ciphertext[text_equals_index] = b'=' ^ key_byte_equals;
    modified_ciphertext[text_semicolon_index] = b';' ^ key_byte_semicolon;

    modified_ciphertext
}

pub fn break_aes_random_rw_ctr() -> Vec<u8> {
    let ciphertext = oracles::ctr_ciphertext();
    let mut output = Vec::new();
    for offset in 0..ciphertext.len() {
        for b in 0..=u8::MAX {
            if oracles::ctr_edit_api(&ciphertext[..], offset, &[b])[offset] == ciphertext[offset] {
                output.push(b);
                break;
            }
        }
    }

    output
}

pub fn break_sucessive_ctr_statistically() -> bool {
    let plaintext_strings = include_str!("../../resources/cryptopals_set3_challenge20.txt")
        .lines()
        .map(|l| base64::decode(l).unwrap())
        .collect::<Vec<Vec<u8>>>();

    let encrypted_strings = oracles::get_key().with(|aes_key| {
        plaintext_strings
            .iter()
            .map(|s| ctr::apply_ctr(s, aes_key).unwrap())
            .collect::<Vec<Vec<u8>>>()
    });
    let min_len_string = encrypted_strings
        .iter()
        .min_by(|s1, s2| s1.len().cmp(&s2.len()))
        .unwrap()
        .len();

    let same_key_encrypted_slices = encrypted_strings.iter().map(|s| &s[..min_len_string]);
    let mut cipher_vector: Vec<u8> = Vec::new();
    &same_key_encrypted_slices.fold(&mut cipher_vector, |acc, v| {
        acc.append(&mut v.to_vec());
        acc
    });

    let possible_keys = challenges::xor::break_repeating_xor(
        &cipher_vector[..],
        Some(4),
        min_len_string as u8..(min_len_string + 1) as u8,
    );

    for key in possible_keys {
        for slice in cipher_vector.chunks(min_len_string) {
            if String::from_utf8(xor::apply_repeating_xor(slice, &key[..])).is_err() {
                return false;
            }
        }
    }

    return true;
}

/* Challenge 19 - AKA - the game of guess will be spared from you
   But here's the code I used to break it, replacing the index and the "key" and checking if the guess was right.
pub fn break_sucessive_ctr_game_of_guess() {
    let guess = &encrypted_strings_pool[37];
    let maybe_key = xor::apply_repeating_xor(&guess, b"He, too, has been changed in his turfs");
    let mut i = 0;
    for trial in &encrypted_strings_pool[..] {
        println!(
            "{} {:?}",
            i,
            &String::from_utf8_lossy(&xor::apply_repeating_xor(&trial[..], &maybe_key[..]))
                .chars()
                .fold(String::new(), |acc, c| format!("{} {}", acc, c))
        );
        i += 1;
    }
}*/
