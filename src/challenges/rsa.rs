use crate::number::ModInverse;
use crate::number::{biguint_to_message, message_to_biguint};
use crate::rsa::RsaCreds;
use num_bigint::{BigUint, ToBigUint};
use num_integer::Integer;
use num_traits::One;
use num_traits::Zero;
use std::borrow::{Borrow, Cow};
use std::ops::Div;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::padding::pkcs_1_5;
    use crate::padding::pkcs_1_5::Pkcs1_5Encrypt;
    const MESSAGE: &[u8] = b"../resources/cryptopals_set1_challenge6.txt";

    #[test]
    fn test_rsa_encrypt_small_message_decrypt() {
        let rsa = RsaCreds::new();
        let ciphertext = rsa.encrypt(b"Hello");

        assert_eq!(b"Hello", &rsa.decrypt(&ciphertext)[..]);
    }

    #[test]
    fn test_rsa_encrypt_small_message_easy_decrypt() {
        let rsa = RsaCreds::new();
        let ciphertext = rsa.encrypt(b"Hello");

        assert_eq!(
            b"Hello",
            &biguint_to_message(&BigUint::from_bytes_be(&ciphertext).cbrt())[..]
        );
    }

    #[test]
    fn test_rsa_broadcast_attack() {
        let get_cipher = |m| {
            let rsa = RsaCreds::new();
            RsaCiphertext::new(rsa.encrypt(m), Cow::Owned(rsa.get_public_key().clone()))
        };

        let cipher1 = get_cipher(MESSAGE);
        let cipher2 = get_cipher(MESSAGE);
        let cipher3 = get_cipher(MESSAGE);

        assert_eq!(
            MESSAGE,
            rsa_e_3_broadcast_attack(&cipher1, &cipher2, &cipher3)
        );
    }

    // this test runs for quite some time, so let's make it optional
    #[test]
    #[ignore]
    fn test_rsa_parity_oracle() {
        const BASE64_SECRET: &[u8] = b"VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==";
        let rsa = RsaCreds::new();
        let ciphertext = rsa.encrypt(&base64::decode(BASE64_SECRET).unwrap());
        assert_eq!(
            base64::decode(BASE64_SECRET).unwrap(),
            decrypt_using_parity_oracle(&rsa, &ciphertext)
        );
    }
    #[test]
    fn test_merge_ranges() {
        let ranges = [
            (
                ToBigUint::to_biguint(&2).unwrap(),
                ToBigUint::to_biguint(&5).unwrap(),
            ),
            (
                ToBigUint::to_biguint(&3).unwrap(),
                ToBigUint::to_biguint(&8).unwrap(),
            ),
            (
                ToBigUint::to_biguint(&1).unwrap(),
                ToBigUint::to_biguint(&8).unwrap(),
            ),
        ];

        assert_eq!(
            merge_ranges(ranges.to_vec()),
            [(
                ToBigUint::to_biguint(&1).unwrap(),
                ToBigUint::to_biguint(&8).unwrap(),
            )]
            .to_vec()
        );
    }

    #[test]
    fn test_rsa_bleichenbacher_padding_oracle_simple() {
        const MESSAGE: &[u8] = b"kick it, CC";
        let rsa = RsaCreds::new_with_key_length(768);
        let ciphertext = rsa.pkcs1_5_encrypt(MESSAGE).unwrap();
        assert_eq!(
            MESSAGE,
            pkcs_1_5::remove_pkcs1_5_for_encryption(&decrypt_using_bleichenbacher_oracle(
                &rsa,
                &ciphertext
            ))
            .unwrap(),
        );
    }
}

pub fn decrypt_using_bleichenbacher_oracle(rsa: &RsaCreds, ciphertext: &[u8]) -> Vec<u8> {
    let ciphertext_as_biguint = message_to_biguint(ciphertext);
    let n = &rsa.get_public_key().1;

    let k = n.bits() as u32 / 8;
    let b = ToBigUint::to_biguint(&2).unwrap().pow((k - 2) * 8);
    let mut message_ranges: Vec<(BigUint, BigUint)> = Vec::new();
    let mut i = 1;
    let mut last_s: BigUint = One::one();

    let message_range = (&b * 2u8, ((&b * 3u8) - 1u8));
    message_ranges.push(message_range);

    loop {
        if i == 1 {
            //  step 2.a
            let mut s1: BigUint = n.div_ceil(&(&b * 3u8));
            while !is_plaintext_pkcs1(
                rsa,
                &biguint_to_message(
                    &(message_to_biguint(&rsa.encrypt(&biguint_to_message(&s1)))
                        * &ciphertext_as_biguint),
                ),
            ) {
                s1 += 0x1u32;
            }

            last_s = s1;
        } else if message_ranges.len() > 1 {
            // step 2.b
            let mut s = last_s.clone();

            while !is_plaintext_pkcs1(
                rsa,
                &biguint_to_message(
                    &(message_to_biguint(&rsa.encrypt(&biguint_to_message(&s)))
                        * &ciphertext_as_biguint),
                ),
            ) {
                s += 1u8;
            }

            last_s = s;
        } else if message_ranges.len() == 1 {
            // step 2.c
            let r2_lower_range =
                (2u8 * ((&message_ranges[0].1 * &last_s) - (2u8 * &b))).div_ceil(n); //floor(n); // that worked for div statistically
            let s_range_calc = |r: BigUint| {
                let lower_range = ((2u8 * &b) + (&r * n)).div_ceil(&message_ranges[0].1);
                let upper_range = ((3u8 * &b) + ((&r) * n)).div(&message_ranges[0].0);
                (lower_range, upper_range)
            };

            let mut found = false;
            let mut r2 = r2_lower_range;
            let (mut s2_lower_range, mut s2_upper_range) = s_range_calc(r2.clone());
            let mut s2: BigUint = Zero::zero();
            while !found {
                s2 = s2_lower_range;
                let mut found_s2 = false;
                while !found_s2 && &s2 <= &s2_upper_range {
                    found_s2 = is_plaintext_pkcs1(
                        rsa,
                        &biguint_to_message(
                            &(message_to_biguint(&rsa.encrypt(&biguint_to_message(&s2)))
                                * &ciphertext_as_biguint),
                        ),
                    );

                    if found_s2 {
                        break;
                    }

                    s2 += 0x1u32;
                }

                found |= found_s2;
                if found {
                    break;
                }
                r2 += 0x1u32;
                let (new_s2_lower_range, new_s2_upper_range) = s_range_calc(r2.clone());
                s2_lower_range = new_s2_lower_range;
                s2_upper_range = new_s2_upper_range;
            }

            last_s = s2;
        } else {
            panic!("Invalid");
        }

        i += 1;
        println!("last s: {:#x}", &last_s);

        // step 3
        let mut new_ranges = Vec::new();
        for range in message_ranges {
            let r_upper;
            let r_lower;

            r_lower = ((&range.0 * &last_s) - (3u8 * &b) + 0x1u8).div_ceil(n);
            r_upper = ((&range.1 * &last_s) - (2u8 * &b)).div(n);
            let r_range = (r_lower, r_upper);
            let mut r = r_range.0.clone();
            while &r <= &r_range.1 {
                new_ranges.push((
                    std::cmp::max(range.0.clone(), (2u8 * &b + &r * n).div_ceil(&last_s)),
                    std::cmp::min(
                        range.1.clone(),
                        ((3u8 * &b) - 1u8 + (&r * n)).div_floor(&last_s),
                    ),
                ));

                r += 1u8;
            }
        }
        message_ranges = new_ranges;
        if message_ranges.len() == 1 && &message_ranges[0].0 == &message_ranges[0].1 {
            return biguint_to_message(&message_ranges[0].0);
        }

        println!("message_range len: {}", message_ranges.len());
        println!("ranges:");
        for range in &message_ranges {
            println!("message range: ({:#x}, {:#x})", &range.0, &range.1);
        }

        println!("before message_range len: {}", message_ranges.len());
        if message_ranges.len() > 1 {
            message_ranges = merge_ranges(message_ranges);
        }
        println!("after message_range len: {}", message_ranges.len());

        /*println!(
            "real message: {:#x}",
            message_to_biguint(&rsa.decrypt(ciphertext))
        );*/

        //print!("***********\n************\n************\n");
    }
}

fn merge_ranges(message_ranges: Vec<(BigUint, BigUint)>) -> Vec<(BigUint, BigUint)> {
    let mut ranges = message_ranges;

    ranges.sort_by(|range1, range2| range1.0.cmp(&range2.0));

    let mut processed_ranges = Vec::new();
    processed_ranges.push(ranges[0].clone());

    for unprocessed_range in &ranges[1..] {
        let mut new_processed_ranges = Vec::new();
        for r in processed_ranges {
            if unprocessed_range.0 >= r.0 {
                if unprocessed_range.1 <= r.1 {
                    new_processed_ranges.push(r.clone());
                } else {
                    if unprocessed_range.0 <= r.1 {
                        new_processed_ranges.push((r.0, unprocessed_range.1.clone()));
                    } else {
                        new_processed_ranges.push(r.clone());
                        new_processed_ranges.push(unprocessed_range.clone());
                    }
                }
            } else {
                new_processed_ranges
                    .push((r.0, std::cmp::max(r.1.clone(), unprocessed_range.1.clone())));
            }
        }
        processed_ranges = new_processed_ranges;
    }

    processed_ranges
}

pub fn divide_to_upper(n1: BigUint, n2: &BigUint) -> BigUint {
    let has_remainder = &n1 % n2;
    let zero: BigUint = Zero::zero();

    if has_remainder > zero {
        return (n1 / n2) + n2;
    } else {
        return n1 / n2;
    }
}

pub fn is_plaintext_pkcs1(rsa: &RsaCreds, ciphertext: &[u8]) -> bool {
    // this is a broken check, but that's what we do here
    // basically checks the padded_message starts with 0 and 2
    let padded_message = rsa.decrypt(ciphertext);
    if padded_message[0] == 2
        && padded_message.len() == ((rsa.get_public_key().1.bits() as usize / 8) - 1)
    {
        return true;
    } else {
        return false;
    }
}

pub fn decrypt_using_parity_oracle(rsa: &RsaCreds, ciphertext: &[u8]) -> Vec<u8> {
    let zero: BigUint = Zero::zero();
    let ciphertext_as_biguint = message_to_biguint(ciphertext);

    // plaintext_range = [0, n]
    let mut plaintext_range = (zero.clone(), rsa.get_public_key().1.clone());
    let two_encrypted =
        message_to_biguint(&rsa.encrypt(&biguint_to_message(&ToBigUint::to_biguint(&2).unwrap())));

    let mut two_power = 1;
    let log_2_n = rsa.get_public_key().1.bits() as u32;

    // is the remainder from dividing by 2^power bigger than n/2 or not?
    // following the answer, in each iteration we reduce the range by 2
    while two_power <= log_2_n {
        if is_plaintext_even(
            rsa,
            &biguint_to_message(&(&two_encrypted.pow(two_power) * &ciphertext_as_biguint)),
        ) {
            plaintext_range.1 = (&plaintext_range.0 + &plaintext_range.1) / 2u8;
        } else {
            plaintext_range.0 = (&plaintext_range.0 + &plaintext_range.1) / 2u8;
        }

        two_power += 1;
        println!(
            "{}",
            String::from_utf8_lossy(&biguint_to_message(&plaintext_range.1))
        );
        println!("range len: {}", &plaintext_range.1 - &plaintext_range.0);
    }

    biguint_to_message(&plaintext_range.1)
}

pub fn is_plaintext_even(rsa: &RsaCreds, ciphertext: &[u8]) -> bool {
    message_to_biguint(&rsa.decrypt(ciphertext)) % ToBigUint::to_biguint(&2).unwrap()
        == ToBigUint::to_biguint(&0).unwrap()
}

pub struct RsaCiphertext<'a> {
    pub ciphertext: Cow<'a, [u8]>,
    pub public_key: Cow<'a, (BigUint, BigUint)>,
}

impl<'a> RsaCiphertext<'a> {
    pub fn new<T, S>(ciphertext: T, public_key: S) -> Self
    where
        T: Into<Cow<'a, [u8]>>,
        S: Into<Cow<'a, (BigUint, BigUint)>>,
    {
        RsaCiphertext {
            ciphertext: ciphertext.into(),
            public_key: public_key.into(),
        }
    }
}

pub fn rsa_e_3_broadcast_attack<'a>(
    cipher0: &RsaCiphertext<'a>,
    cipher1: &RsaCiphertext<'a>,
    cipher2: &RsaCiphertext<'a>,
) -> Vec<u8> {
    let total_mod = &cipher0.public_key.1 * &cipher1.public_key.1 * &cipher2.public_key.1;
    let m_s_0 = &cipher1.public_key.1 * &cipher2.public_key.1;
    let m_s_1 = &cipher0.public_key.1 * &cipher2.public_key.1;
    let m_s_2 = &cipher0.public_key.1 * &cipher1.public_key.1;

    let c_0 = BigUint::from_bytes_be(cipher0.ciphertext.borrow()) % &cipher0.public_key.1;
    let c_1 = BigUint::from_bytes_be(cipher1.ciphertext.borrow()) % &cipher1.public_key.1;
    let c_2 = BigUint::from_bytes_be(cipher2.ciphertext.borrow()) % &cipher2.public_key.1;

    let result = ((&c_0 * &m_s_0 * m_s_0.invmod(&cipher0.public_key.1).unwrap())
        + (&c_1 * &m_s_1 * m_s_1.invmod(&cipher1.public_key.1).unwrap())
        + (&c_2 * &m_s_2 * m_s_2.invmod(&cipher2.public_key.1).unwrap()))
        % (&total_mod);
    biguint_to_message(&result.cbrt())
}
