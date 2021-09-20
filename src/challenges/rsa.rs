use crate::rsa::{biguint_to_message, ModInverse};
use num_bigint::BigUint;
use std::borrow::{Borrow, Cow};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rsa::RsaCreds;
    const MESSAGE: &[u8] = b"../resources/cryptopals_set1_challenge6.txt";

    #[test]
    fn test_rsa_encrypt_small_message_easy_decrypt() {
        let rsa = RsaCreds::new();
        let ciphertext = rsa.encrypt(b"Hello");

        assert_eq!(
            "Hello",
            String::from_utf8(biguint_to_message(
                &BigUint::from_bytes_le(&ciphertext).cbrt()
            ))
            .unwrap()
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

    let c_0 = BigUint::from_bytes_le(cipher0.ciphertext.borrow()) % &cipher0.public_key.1;
    let c_1 = BigUint::from_bytes_le(cipher1.ciphertext.borrow()) % &cipher1.public_key.1;
    let c_2 = BigUint::from_bytes_le(cipher2.ciphertext.borrow()) % &cipher2.public_key.1;

    let result = ((&c_0 * &m_s_0 * m_s_0.invmod(&cipher0.public_key.1).unwrap())
        + (&c_1 * &m_s_1 * m_s_1.invmod(&cipher1.public_key.1).unwrap())
        + (&c_2 * &m_s_2 * m_s_2.invmod(&cipher2.public_key.1).unwrap()))
        % (&total_mod);
    biguint_to_message(&result.cbrt())
}
