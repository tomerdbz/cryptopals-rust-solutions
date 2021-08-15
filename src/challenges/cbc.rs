use crate::challenges;
use challenges::oracles;

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_cbc_challenge_cant_put_admin() {
        let encrypted = oracles::cbc_challenge_ciphertext_oracle(b"hello;admin=true");

        assert_eq!(
            oracles::cbc_challenge_decrypt_cipher_search_admin(&encrypted[..]),
            false
        );
    }

    #[test]
    fn test_cbc_challenge_make_admin() {
        let encrypted = cbc_challenge_make_admin();

        assert_eq!(
            oracles::cbc_challenge_decrypt_cipher_search_admin(&encrypted[..]),
            true
        );
    }
}

pub fn cbc_challenge_make_admin() -> Vec<u8> {
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
    let mut should_proceed = false;
    use rand::prelude::*;

    let mut rng = rand::thread_rng();
    while !should_proceed {
        // the dont cares must not contain = or ; or else the offsets will be broken because of quotes
        let prepend_dont_cares: Vec<u8> = (0..16).map(|_| rng.gen_range(0..b';' - 1)).collect();
        let mut ciphertext = oracles::cbc_challenge_ciphertext_oracle(
            &[&prepend_dont_cares[..], b":admin<true:"].concat(),
        );
        let third_block_first_byte = ciphertext[16 * 2];
        let third_block_sixth_byte = ciphertext[16 * 2 + 6];
        let third_block_eleventh_byte = ciphertext[16 * 2 + 11];
        should_proceed = third_block_first_byte % 2 == 1
            && third_block_sixth_byte % 2 == 1
            && third_block_eleventh_byte % 2 == 1;
        if should_proceed {
            ciphertext[16 * 2] = third_block_first_byte - 1;
            ciphertext[16 * 2 + 6] = third_block_sixth_byte - 1;
            ciphertext[16 * 2 + 11] = third_block_eleventh_byte - 1;

            return ciphertext;
        }
    }

    // ok..be quiet now
    return Vec::new();
}
